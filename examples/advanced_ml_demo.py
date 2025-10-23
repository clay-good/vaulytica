#!/usr/bin/env python3
"""
Vaulytica Advanced ML Demo

Demonstrates deep learning and AutoML capabilities:
- LSTM sequence modeling
- Transformer with attention
- Model ensembles
- AutoML optimization
- Model explainability
- Model persistence

Author: World-Class Software Engineering Team
Version: 0.12.0
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
import random

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from vaulytica.advanced_ml import (
    AdvancedMLEngine, ModelConfig, ModelType, EnsembleMethod,
    LSTMModel, TransformerModel, EnsembleModel, AutoMLEngine
)
from vaulytica.ml_engine import MLFeatures, FeatureExtractor
from vaulytica.threat_intel import ThreatLevel
from vaulytica.models import SecurityEvent, EventCategory, Severity


def create_sample_sequences(num_sequences: int = 20) -> tuple:
    """Create sample event sequences for training."""
    sequences = []
    labels = []
    
    # Create feature extractor
    extractor = FeatureExtractor()
    
    for i in range(num_sequences):
        sequence_length = random.randint(5, 15)
        sequence = []
        
        # Determine threat level for this sequence
        threat_level = random.choice([
            ThreatLevel.BENIGN, ThreatLevel.LOW, ThreatLevel.MEDIUM,
            ThreatLevel.HIGH, ThreatLevel.CRITICAL
        ])
        
        # Create sequence of events
        for j in range(sequence_length):
            # Create event based on threat level
            if threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                severity = random.choice([Severity.CRITICAL, Severity.HIGH])
                category = random.choice([
                    EventCategory.MALWARE,
                    EventCategory.UNAUTHORIZED_ACCESS,
                    EventCategory.DATA_EXFILTRATION
                ])
                failed_logins = random.randint(10, 50)
                data_transfer = random.uniform(100, 1000)
            elif threat_level == ThreatLevel.MEDIUM:
                severity = random.choice([Severity.MEDIUM, Severity.HIGH])
                category = random.choice([
                    EventCategory.POLICY_VIOLATION,
                    EventCategory.VULNERABILITY
                ])
                failed_logins = random.randint(3, 10)
                data_transfer = random.uniform(10, 100)
            else:
                severity = random.choice([Severity.LOW, Severity.INFO])
                category = random.choice([
                    EventCategory.RECONNAISSANCE,
                    EventCategory.UNKNOWN
                ])
                failed_logins = random.randint(0, 2)
                data_transfer = random.uniform(0, 10)
            
            # Create event
            event = SecurityEvent(
                event_id=f"evt_{i}_{j}",
                timestamp=datetime.utcnow() - timedelta(hours=random.randint(0, 24)),
                source_system="demo",
                severity=severity,
                category=category,
                title=f"Sample event {i}-{j}",
                description=f"Demo event for sequence {i}",
                raw_event={"demo": True},
                source_ip=f"192.168.1.{random.randint(1, 254)}",
                destination_ip=f"10.0.0.{random.randint(1, 254)}",
                user=f"user{random.randint(1, 10)}",
                affected_resources=[f"resource{random.randint(1, 5)}"]
            )
            
            # Extract features
            features = extractor.extract_features(event, [])
            
            # Adjust features based on threat level
            features.failed_login_count = failed_logins
            features.data_transfer_mb = data_transfer

            # Map threat level to score
            threat_scores = {
                ThreatLevel.BENIGN: 0.0,
                ThreatLevel.LOW: 0.2,
                ThreatLevel.MEDIUM: 0.5,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.CRITICAL: 1.0,
                ThreatLevel.UNKNOWN: 0.1
            }
            features.threat_intel_score = threat_scores.get(threat_level, 0.0)
            
            sequence.append(features)
        
        sequences.append(sequence)
        labels.append(threat_level)
    
    return sequences, labels


def demo_lstm_model():
    """Demonstrate LSTM model."""
    print("\n" + "="*80)
    print("1. LSTM MODEL DEMONSTRATION")
    print("="*80)
    
    # Create config
    config = ModelConfig(
        model_type=ModelType.LSTM,
        hidden_size=128,
        num_layers=2,
        sequence_length=10
    )
    
    # Create model
    print("\n📊 Creating LSTM model...")
    lstm = LSTMModel(config)
    print(f"   ✓ Hidden size: {lstm.hidden_size}")
    print(f"   ✓ Layers: {lstm.num_layers}")
    print(f"   ✓ Sequence length: {lstm.sequence_length}")
    
    # Create training data
    print("\n📝 Generating training sequences...")
    sequences, labels = create_sample_sequences(20)
    print(f"   ✓ Created {len(sequences)} sequences")
    print(f"   ✓ Label distribution: {dict((l.value, labels.count(l)) for l in set(labels))}")
    
    # Train
    print("\n🎓 Training LSTM model...")
    metrics = lstm.train(sequences, labels)
    print(f"   ✓ Accuracy: {metrics.accuracy:.4f}")
    print(f"   ✓ F1 Score: {metrics.f1_score:.4f}")
    print(f"   ✓ Training time: {metrics.training_time:.2f}s")
    
    # Predict
    print("\n🔮 Making predictions...")
    test_sequence = sequences[0]
    threat_level, confidence, attention = lstm.predict(test_sequence)
    print(f"   ✓ Predicted threat: {threat_level.value}")
    print(f"   ✓ Confidence: {confidence:.4f}")
    print(f"   ✓ Attention weights: {len(attention)} timesteps")
    
    return lstm, sequences, labels


def demo_transformer_model(sequences, labels):
    """Demonstrate Transformer model."""
    print("\n" + "="*80)
    print("2. TRANSFORMER MODEL DEMONSTRATION")
    print("="*80)
    
    # Create config
    config = ModelConfig(
        model_type=ModelType.TRANSFORMER,
        hidden_size=128,
        attention_heads=4,
        sequence_length=10
    )
    
    # Create model
    print("\n📊 Creating Transformer model...")
    transformer = TransformerModel(config)
    print(f"   ✓ Hidden size: {transformer.hidden_size}")
    print(f"   ✓ Attention heads: {transformer.num_heads}")
    print(f"   ✓ Sequence length: {transformer.sequence_length}")
    
    # Train
    print("\n🎓 Training Transformer model...")
    metrics = transformer.train(sequences, labels)
    print(f"   ✓ Accuracy: {metrics.accuracy:.4f}")
    print(f"   ✓ F1 Score: {metrics.f1_score:.4f}")
    print(f"   ✓ Training time: {metrics.training_time:.2f}s")
    
    # Predict
    print("\n🔮 Making predictions with attention...")
    test_sequence = sequences[0]
    threat_level, confidence, attention = transformer.predict(test_sequence)
    print(f"   ✓ Predicted threat: {threat_level.value}")
    print(f"   ✓ Confidence: {confidence:.4f}")
    print(f"   ✓ Multi-head attention: {len(attention)} values")
    
    return transformer


def demo_ensemble_model(lstm, transformer, sequences, labels):
    """Demonstrate ensemble model."""
    print("\n" + "="*80)
    print("3. ENSEMBLE MODEL DEMONSTRATION")
    print("="*80)
    
    # Create config
    config = ModelConfig(
        model_type=ModelType.ENSEMBLE,
        ensemble_method=EnsembleMethod.WEIGHTED,
        ensemble_weights=[0.6, 0.4]  # Favor LSTM slightly
    )
    
    # Create ensemble
    print("\n📊 Creating ensemble model...")
    ensemble = EnsembleModel(config, [lstm, transformer])
    print(f"   ✓ Models: {len(ensemble.models)}")
    print(f"   ✓ Method: {ensemble.method.value}")
    print(f"   ✓ Weights: {ensemble.weights}")
    
    # Train
    print("\n🎓 Training ensemble...")
    metrics = ensemble.train(sequences, labels)
    print(f"   ✓ Accuracy: {metrics.accuracy:.4f}")
    print(f"   ✓ F1 Score: {metrics.f1_score:.4f}")
    print(f"   ✓ Training time: {metrics.training_time:.2f}s")
    
    # Predict
    print("\n🔮 Making ensemble predictions...")
    test_sequence = sequences[0]
    threat_level, confidence, details = ensemble.predict(test_sequence)
    print(f"   ✓ Ensemble prediction: {threat_level.value}")
    print(f"   ✓ Ensemble confidence: {confidence:.4f}")
    print(f"   ✓ Individual predictions: {details['individual_predictions']}")
    print(f"   ✓ Individual confidences: {[f'{c:.3f}' for c in details['individual_confidences']]}")
    
    return ensemble


def demo_automl(sequences, labels):
    """Demonstrate AutoML."""
    print("\n" + "="*80)
    print("4. AUTOML DEMONSTRATION")
    print("="*80)
    
    # Create config
    config = ModelConfig(
        model_type=ModelType.AUTOML,
        automl_iterations=10,  # Limited for demo
        automl_timeout=60
    )
    
    # Create AutoML engine
    print("\n📊 Creating AutoML engine...")
    automl = AutoMLEngine(config)
    print(f"   ✓ Max iterations: {config.automl_iterations}")
    print(f"   ✓ Timeout: {config.automl_timeout}s")
    
    # Run optimization
    print("\n🔍 Running AutoML optimization...")
    print("   (This may take a minute...)")
    result = automl.optimize(sequences, labels)
    
    print(f"\n   ✓ Best model: {result.best_model_type.value}")
    print(f"   ✓ Best score: {result.best_score:.4f}")
    print(f"   ✓ Total trials: {result.total_trials}")
    print(f"   ✓ Optimization time: {result.optimization_time:.2f}s")
    print(f"\n   Best configuration:")
    print(f"     - Hidden size: {result.best_config.hidden_size}")
    print(f"     - Layers: {result.best_config.num_layers}")
    print(f"     - Sequence length: {result.best_config.sequence_length}")
    
    return automl


def demo_explainability(engine, sequences):
    """Demonstrate model explainability."""
    print("\n" + "="*80)
    print("5. MODEL EXPLAINABILITY DEMONSTRATION")
    print("="*80)
    
    print("\n🔍 Generating explanation for prediction...")
    test_sequence = sequences[0]
    
    explanation = engine.explain(test_sequence)
    
    print(f"\n{explanation.explanation_text}")
    
    print("\n   Top 5 features by importance:")
    for i, (feature, importance) in enumerate(explanation.top_features, 1):
        print(f"     {i}. {feature}: {importance:+.4f}")
    
    if explanation.attention_weights:
        print(f"\n   ✓ Attention weights available: {len(explanation.attention_weights)} timesteps")


def demo_persistence(engine):
    """Demonstrate model persistence."""
    print("\n" + "="*80)
    print("6. MODEL PERSISTENCE DEMONSTRATION")
    print("="*80)
    
    # Save model
    print("\n💾 Saving model...")
    model_name = "demo_model"
    engine.save_model(model_name)
    print(f"   ✓ Model saved: {model_name}")
    
    # List models
    print("\n📋 Available models:")
    models = engine.list_models()
    for model in models:
        print(f"   - {model}")
    
    # Load model
    print(f"\n📂 Loading model...")
    engine.load_model(model_name)
    print(f"   ✓ Model loaded: {model_name}")


def main():
    """Run all demonstrations."""
    print("="*80)
    print("🚀 VAULYTICA ADVANCED ML DEMONSTRATION")
    print("="*80)
    print("\nThis demo showcases:")
    print("  • LSTM sequence modeling")
    print("  • Transformer with multi-head attention")
    print("  • Model ensembles with voting")
    print("  • AutoML hyperparameter optimization")
    print("  • Model explainability (SHAP-like)")
    print("  • Model persistence (save/load)")
    print()
    
    # Create engine
    engine = AdvancedMLEngine()
    
    # Demo 1: LSTM
    lstm, sequences, labels = demo_lstm_model()
    
    # Demo 2: Transformer
    transformer = demo_transformer_model(sequences, labels)
    
    # Demo 3: Ensemble
    ensemble = demo_ensemble_model(lstm, transformer, sequences, labels)
    
    # Set ensemble as active
    engine.ensemble_model = ensemble
    engine.active_model = ensemble
    engine.model_type = ModelType.ENSEMBLE
    
    # Demo 4: AutoML
    demo_automl(sequences, labels)
    
    # Demo 5: Explainability
    demo_explainability(engine, sequences)
    
    # Demo 6: Persistence
    demo_persistence(engine)
    
    # Final stats
    print("\n" + "="*80)
    print("📊 FINAL STATISTICS")
    print("="*80)
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"   {key.replace('_', ' ').title()}: {value}")
    
    print("\n" + "="*80)
    print("✅ ADVANCED ML DEMONSTRATION COMPLETE!")
    print("="*80)
    print("\n💡 Next steps:")
    print("   • Integrate with Security Analyst Agent")
    print("   • Add to dashboard for real-time predictions")
    print("   • Train on production data")
    print("   • Deploy models to production")
    print()


if __name__ == "__main__":
    main()

