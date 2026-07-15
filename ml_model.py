"""ML module — numpy + scikit-learn only (no pandas)."""
import os
import random
import numpy as np
from config import MODEL_PATH, MODELS_DIR

LABELS = ['normal','port_scan','ping_flood','syn_flood','brute_force','ddos']
_PROTO = {'TCP':0,'UDP':1,'ICMP':2,'HTTP':3,'HTTPS':4,'DNS':5,'OTHER':6}
_FLAGS = {'S':1,'SA':2,'A':3,'F':4,'PA':5,'R':6,'':0}


def _feat(proto, packet_size, port=0, ttl=64, flags='', duration=0, sb=0, db=0):
    return [_PROTO.get(proto,6), packet_size, duration,
            _FLAGS.get(str(flags),0), port, ttl, sb, db]


def generate_training_data(n=3000):
    X, y = [], []
    for _ in range(n):
        label = random.choice(LABELS)
        if label == 'normal':
            row = [random.randint(0,6), random.randint(64,1400), random.uniform(0,10),
                   random.randint(0,5), random.randint(1,1024), random.randint(32,128),
                   random.randint(100,5000), random.randint(100,5000)]
        elif label == 'port_scan':
            row = [0, random.randint(40,100), random.uniform(0,1),
                   1, random.randint(1,65535), random.randint(32,64), 40, 0]
        elif label == 'ping_flood':
            row = [2, random.randint(64,128), random.uniform(0,0.1),
                   0, 0, random.randint(60,128), 64, 0]
        elif label == 'syn_flood':
            row = [0, random.randint(40,60), random.uniform(0,0.01),
                   1, random.randint(1,1024), random.randint(32,64), 40, 0]
        elif label == 'brute_force':
            row = [0, random.randint(200,500), random.uniform(0,2),
                   3, random.choice([22,21,3389]), random.randint(64,128),
                   random.randint(200,500), random.randint(100,300)]
        else:
            row = [random.randint(0,2), random.randint(64,1500), random.uniform(0,0.01),
                   random.randint(0,5), random.randint(1,65535), random.randint(32,128),
                   random.randint(64,9000), random.randint(0,100)]
        X.append(row)
        y.append(LABELS.index(label))
    return np.array(X, dtype=float), np.array(y)


def train_model(algorithm='random_forest'):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    import joblib

    print("[ML] Generating training data...")
    X, y = generate_training_data(3000)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)

    models = {
        'random_forest':       RandomForestClassifier(n_estimators=50, random_state=42),
        'decision_tree':       DecisionTreeClassifier(random_state=42),
        'knn':                 KNeighborsClassifier(n_neighbors=5),
        'logistic_regression': LogisticRegression(max_iter=500, random_state=42),
    }
    model = models.get(algorithm, models['random_forest'])
    print(f"[ML] Training {algorithm}...")
    model.fit(Xtr, ytr)
    acc = accuracy_score(yte, model.predict(Xte))
    print(f"[ML] Accuracy: {acc:.2%}")

    os.makedirs(MODELS_DIR, exist_ok=True)
    import joblib
    joblib.dump({'model': model, 'algorithm': algorithm,
                 'accuracy': acc, 'labels': LABELS}, MODEL_PATH)
    print(f"[ML] Saved to {MODEL_PATH}")
    return acc


def predict(protocol='TCP', packet_size=500, port=80, ttl=64, flags='',
            duration=0, src_bytes=0, dst_bytes=0):
    try:
        import joblib
        if not os.path.exists(MODEL_PATH):
            return 'normal', 0.0
        data  = joblib.load(MODEL_PATH)
        X     = np.array([_feat(protocol, packet_size, port, ttl, flags,
                                duration, src_bytes, dst_bytes)], dtype=float)
        idx   = data['model'].predict(X)[0]
        conf  = float(data['model'].predict_proba(X)[0][idx])
        return LABELS[idx], conf
    except Exception:
        return 'normal', 0.0


def get_model_info():
    try:
        import joblib
        if not os.path.exists(MODEL_PATH):
            return None
        d = joblib.load(MODEL_PATH)
        return {'algorithm': d.get('algorithm','unknown'),
                'accuracy':  d.get('accuracy', 0),
                'labels':    d.get('labels', [])}
    except Exception:
        return None
