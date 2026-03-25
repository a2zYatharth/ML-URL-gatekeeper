import pandas as pd
import random
import os

def generate_dataset(num_samples=1000):
    data = []
    for _ in range(num_samples):
        # 50/50 split between Benign (0) and Malicious (1)
        is_malicious = random.choice([0, 1])
        
        if is_malicious:
            # Malicious characteristic profiles (e.g., DGA domains, hidden iframes, new infra)
            row = {
                "url_length": random.randint(50, 150),
                "dot_count": random.randint(3, 8),
                "at_symbol_present": random.choice([0, 0, 1]), # Occasional credential passing
                "hyphen_count": random.randint(2, 6),
                "digit_to_letter_ratio": round(random.uniform(0.1, 0.6), 3),
                "iframe_count": random.randint(1, 5),
                "hidden_forms": random.randint(0, 3),
                "password_fields": random.randint(0, 2),
                "external_link_ratio": round(random.uniform(0.6, 1.0), 3),
                "empty_anchors": random.randint(5, 20),
                "domain_age_days": random.randint(-1, 45), # -1 or very new
                "ssl_days_to_expire": random.randint(-1, 30), # -1 or expiring soon
                "label": 1
            }
        else:
            # Benign characteristic profiles (e.g., clean URLs, established infra)
            row = {
                "url_length": random.randint(20, 60),
                "dot_count": random.randint(1, 3),
                "at_symbol_present": 0,
                "hyphen_count": random.randint(0, 2),
                "digit_to_letter_ratio": round(random.uniform(0.0, 0.1), 3),
                "iframe_count": random.randint(0, 1),
                "hidden_forms": 0,
                "password_fields": random.randint(0, 1),
                "external_link_ratio": round(random.uniform(0.0, 0.3), 3),
                "empty_anchors": random.randint(0, 3),
                "domain_age_days": random.randint(300, 3650),
                "ssl_days_to_expire": random.randint(90, 365),
                "label": 0
            }
        data.append(row)

    df = pd.DataFrame(data)
    
    # Ensure the data directory exists
    os.makedirs("data", exist_ok=True)
    file_path = "data/training_data.csv"
    df.to_csv(file_path, index=False)
    print(f"[+] Successfully generated {num_samples} mock records at {file_path}")

if __name__ == "__main__":
    generate_dataset()