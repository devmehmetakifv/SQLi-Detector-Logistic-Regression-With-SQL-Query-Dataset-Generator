"""
SQLi Detection API
Loads all 4 model generations and provides prediction endpoints.
"""

from flask import Flask, request, jsonify
import joblib
import os
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Model storage
models = {}

def load_models():
    """Load all 4 generation models and vectorizers."""
    models_dir = os.path.join(os.path.dirname(__file__), 'models')
    
    for gen in range(1, 5):
        model_path = os.path.join(models_dir, f'gen{gen}_model.joblib')
        vectorizer_path = os.path.join(models_dir, f'gen{gen}_vectorizer.joblib')
        
        if os.path.exists(model_path) and os.path.exists(vectorizer_path):
            try:
                models[f'gen{gen}'] = {
                    'model': joblib.load(model_path),
                    'vectorizer': joblib.load(vectorizer_path)
                }
                logger.info(f"Loaded Generation {gen} model successfully")
            except Exception as e:
                logger.error(f"Failed to load Generation {gen}: {e}")
        else:
            logger.warning(f"Generation {gen} files not found")
    
    logger.info(f"Total models loaded: {len(models)}")

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for Docker."""
    return jsonify({
        'status': 'healthy',
        'models_loaded': len(models)
    })

@app.route('/predict', methods=['POST'])
def predict():
    """
    Analyze one or more inputs for SQLi using all loaded models.
    
    Request body:
        {"input": "user input"} or
        {"inputs": [{"id": "raw_payload", "text": "..."}, {"id": "full_query", "text": "..."}]}
    
    Response:
        {
            "inputs": [
                {
                    "id": "raw_payload",
                    "text": "...",
                    "predictions": {
                        "gen1": {"detected": true/false, "probability": 0.95, "label": "Malicious/Benign"},
                        ...
                    }
                },
                ...
            ],
            "models": ["gen1", ...]
        }
    """
    try:
        data = request.get_json()
        
        if not data or ('input' not in data and 'inputs' not in data):
            return jsonify({'error': 'Provide "input" or "inputs" array'}), 400

        # Build list of inputs to score
        inputs_to_score = []
        if 'inputs' in data and isinstance(data['inputs'], list):
            for item in data['inputs']:
                text = item.get('text') if isinstance(item, dict) else None
                if not text:
                    continue
                inputs_to_score.append({
                    'id': item.get('id') or f'input_{len(inputs_to_score)+1}',
                    'text': text
                })
        elif 'input' in data:
            inputs_to_score.append({'id': 'input', 'text': data['input']})

        if not inputs_to_score:
            return jsonify({'error': 'No valid inputs supplied'}), 400

        input_results = []

        for input_item in inputs_to_score:
            user_input = input_item['text']
            
            # Normalize input (same as training)
            normalized = ' '.join(user_input.split())
            
            predictions = {}
            
            for gen_name, gen_data in models.items():
                try:
                    vectorizer = gen_data['vectorizer']
                    model = gen_data['model']
                    
                    # Transform input
                    features = vectorizer.transform([normalized])
                    
                    # Predict
                    prediction = model.predict(features)[0]
                    probability = model.predict_proba(features)[0]
                    
                    # Probability of malicious (class 1)
                    mal_prob = probability[1] if len(probability) > 1 else probability[0]
                    
                    predictions[gen_name] = {
                        'detected': bool(prediction == 1),
                        'probability': round(float(mal_prob), 4),
                        'label': 'Malicious' if prediction == 1 else 'Benign'
                    }
                except Exception as e:
                    logger.error(f"Prediction error for {gen_name}: {e}")
                    predictions[gen_name] = {
                        'detected': False,
                        'probability': 0.0,
                        'label': 'Error',
                        'error': str(e)
                    }

            input_results.append({
                'id': input_item['id'],
                'text': user_input,
                'predictions': predictions
            })
        
        return jsonify({
            'inputs': input_results,
            'models': list(models.keys())
        })
    
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/models', methods=['GET'])
def list_models():
    """List all loaded models."""
    return jsonify({
        'models': list(models.keys()),
        'count': len(models)
    })

if __name__ == '__main__':
    # Load models on startup
    load_models()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
