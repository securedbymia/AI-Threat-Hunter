import pandas as pd
import os

print("📂 Attempting to load file...")

# File path
file_path = r'C:\\Users\\Chi-chi\\Downloads\\AI-Threat-Hunter\\TrafficLabelling\\Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'

# Check if file exists
if os.path.exists(file_path):
    try:
        df = pd.read_csv(file_path, encoding='ISO-8859-1', on_bad_lines='skip')
        print("✅ File loaded successfully!\n")
        print("🧾 Columns in the dataset:\n")
        print(df.columns)

        # Clean column names (strip spaces)
        df.columns = df.columns.str.strip()

        # Check for missing values
        missing_values = df.isnull().sum()

        # Show columns with missing data
        print("Missing values in columns:\n", missing_values[missing_values > 0])

        missing_data_option = input("Would you like to (1) drop rows with missing values or (2) fill missing values with the mean? (Enter 1 or 2): ")

        if missing_data_option == '1':
            df = df.dropna()  # Option 1: Drop rows with missing values
            print("✅ Rows with missing values dropped.")
        elif missing_data_option == '2':
            df = df.fillna(df.mean())  # Option 2: Fill missing values with column means
            print("✅ Missing values filled with column means.")
        else:
            print("❌ Invalid option chosen. No changes made.")

        # Convert 'Flow Duration' to numeric
        df['Flow Duration'] = pd.to_numeric(df['Flow Duration'], errors='coerce')

        # Convert 'Label' to categorical
        df['Label'] = df['Label'].astype('category')

        # Drop irrelevant columns like 'Flow ID'
        df = df.drop(columns=['Flow ID'])

        # Encode 'Label' (BENIGN -> 0, MALICIOUS -> 1)
        df['Label'] = df['Label'].map({'BENIGN': 0, 'MALICIOUS': 1})

        df = df.apply(pd.to_numeric, errors='ignore')
        print(df.dtypes)
        print(df.head())

    except Exception as e:
        print(f"❌ Error loading file: {e}")
else:
    print("❌ File not found at the specified path.")


# Anomaly Detection Model: Isolation Forest (IForest)
# Feature Scaling: Benefits from Standard scaling (StandardScaler) or Min-Max scaling
# Data Split: Split data into a training set and a test set to see model performance

from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

X = df.drop(columns=['Label'])  # Drop the label column to isolate features
y = df['Label']  # Target: 0 = BENIGN, 1 = MALICIOUS

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42
)
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(X_train)


y_pred_train = model.predict(X_train)
y_pred_test = model.predict(X_test)


from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA

y_pred_train = (y_pred_train == 1).astype(int)
y_pred_test = (y_pred_test == 1).astype(int)

print("Training Set Performance:")
print(classification_report(y_train, y_pred_train))
print("Test Set Performance:")
print(classification_report(y_test, y_pred_test))

# Plotting with PCA 
# Reduce features to 2D for visualization
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)

# Create the PCA plot
plt.figure(figsize=(10, 6))
plt.scatter(X_pca[:, 0], X_pca[:, 1], c=y_pred_test, cmap='coolwarm', label='Anomaly Prediction')
plt.title('Anomaly Detection Visualization')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.colorbar(label='Prediction')
plt.legend()
plt.show()


from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt

scaler = StandardScaler()
X_scaled = scaler.fit_transform(df.drop(columns=['Label'])) 
pca = PCA(n_components=0.95)
X_pca = pca.fit_transform(X_scaled)
print(f"Original shape: {df.shape}")
print(f"Reduced shape: {X_pca.shape}")

from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import seaborn as sns

# Initialize the Isolation Forest model
iso_forest = IsolationForest(n_estimators=100, contamination=0.1)  # Contamination should be set based on anomaly percent
iso_forest.fit(df_pca)
predictions = iso_forest.predict(df_pca)
df['Anomaly'] = (predictions == -1).astype(int)  # Directly map -1 (anomaly) to 1 and 1 (normal) to 0
# check
print(df[['Label', 'Anomaly']].head())

# Step 6: Visualize anomalies using scatter plot
plt.figure(figsize=(10, 6))
sns.scatterplot(x=df_pca[:, 0], y=df_pca[:, 1], hue=df['Anomaly'], palette='coolwarm', marker='o')
plt.title('Anomaly Detection Visualization with Isolation Forest')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.legend(title='Anomaly', loc='upper right')
plt.show()


import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import classification_report

plt.figure(figsize=(10, 6))
sns.scatterplot(x=df_pca[:, 0], y=df_pca[:, 1], hue=df['Anomaly'], palette={0: 'green', 1: 'red'}, legend='full')
plt.title('Anomaly Detection - Isolation Forest')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.show()
print("Model Evaluation:")
print(classification_report(df['Label'], df['Anomaly']))

# example
mitre_mapping = {
    'Port 80': {'tactic': 'Execution', 'technique': 'T1071: Application Layer Protocol (HTTP)'},
    'Port 443': {'tactic': 'Exfiltration', 'technique': 'T1041: Exfiltration Over Web Service'},
    'Port 53': {'tactic': 'Exfiltration', 'technique': 'T1071: Application Layer Protocol (DNS tunneling)'},
    'Port 22': {'tactic': 'Persistence', 'technique': 'T1071: Remote Access (SSH)'},
    'Port 445': {'tactic': 'Privilege Escalation', 'technique': 'T1203: Exploitation for Client Execution (SMB)'}
}
print("\nMITRE ATT&CK Mapping Example:")
for port, mapping in mitre_mapping.items():
    print(f"{port}: {mapping['tactic']} -> {mapping['technique']}")


import pandas as pd
from sklearn.preprocessing import StandardScaler

# Define MITRE ATT&CK mapping based on destination port
mitre_mapping = {
    '80': {'tactic': 'Execution', 'technique': 'T1071: Application Layer Protocol (HTTP)'},
    '443': {'tactic': 'Exfiltration', 'technique': 'T1041: Exfiltration Over Web Service'},
}

def map_to_mitre(row):
    port = str(row.get('Destination Port', ''))  # string
    return mitre_mapping.get(port, {'tactic': 'Unknown', 'technique': 'Unknown'})
df['MITRE Mapping'] = df.apply(map_to_mitre, axis=1)

# Feature scaling
X = df.drop(columns=['Label'], errors='ignore')  # Only drop label if it exists
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
print(df[['Label', 'MITRE Mapping']].head())


model = IsolationForest(contamination=0.1)
model.fit(X_scaled)
y_pred = model.predict(X_scaled)
y_pred = [1 if x == 1 else 0 for x in y_pred]  # 1 = normal, 0 = anomaly

df['Anomaly'] = y_pred
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler

# Perform PCA for visualization 
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
# Apply the MITRE Mapping function
df['MITRE Mapping'] = df.apply(map_to_mitre, axis=1)

# Anomaly detection visualization
plt.figure(figsize=(10, 6))
sns.scatterplot(x=X_pca[:, 0], y=X_pca[:, 1], hue=df['Anomaly'], palette={0: 'red', 1: 'green'})
plt.title('Anomaly Detection with Isolation Forest')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.legend(title='Anomaly', loc='best')
plt.show()

# Distribution of MITRE tactics in detected anomalies
tactics_counts = df['MITRE Mapping'].apply(lambda x: x['tactic']).value_counts()
plt.figure(figsize=(8, 6))
sns.barplot(x=tactics_counts.index, y=tactics_counts.values)
plt.title('Distribution of MITRE Tactics in Detected Anomalies')
plt.ylabel('Frequency')
plt.xlabel('MITRE Tactics')
plt.xticks(rotation=45)
plt.tight_layout()  
plt.show()

scaler = StandardScaler()
X_scaled = scaler.fit_transform(df.drop(columns=['Label']))  # Exclude 'Label' for scaling

from sklearn.decomposition import PCA

# Apply PCA
pca = PCA(n_components=2) 
X_pca = pca.fit_transform(X_scaled)

from sklearn.ensemble import IsolationForest

# Train Isolation Forest model
iso_forest = IsolationForest(n_estimators=100, contamination=0.1) 
iso_forest.fit(X_pca)  # Fit model on PCA

predictions = iso_forest.predict(X_pca)

# Convert to a more interpretable format: 0 for normal, 1 for anomaly
predictions = [0 if x == 1 else 1 for x in predictions]
df['Anomaly'] = predictions  # Add predictions 

from sklearn.metrics import classification_report
print(classification_report(df['Label'], df['Anomaly']))

import seaborn as sns
import matplotlib.pyplot as plt

# Scatter plot of PCA 
plt.figure(figsize=(10, 6))
sns.scatterplot(x=X_pca[:, 0], y=X_pca[:, 1], hue=df['Anomaly'], palette={0: 'green', 1: 'red'})
plt.title('Anomaly Detection with Isolation Forest')
plt.xlabel('Principal Component 1')
plt.ylabel('Principal Component 2')
plt.show()

# Map anomalies to MITRE tactics/techniques 
def map_to_mitre(row):
    port = row.get('Destination Port', None)  
    mitre_mapping = {
        '80': {'tactic': 'Execution', 'technique': 'T1071: Application Layer Protocol (HTTP)'},
        '443': {'tactic': 'Exfiltration', 'technique': 'T1041: Exfiltration Over Web Service'},
    }
    return mitre_mapping.get(port, {'tactic': 'Unknown', 'technique': 'Unknown'})

# Apply the mapping function to each row
df['MITRE Mapping'] = df.apply(map_to_mitre, axis=1)

tactics_counts = df['MITRE Mapping'].apply(lambda x: x['tactic']).value_counts()
sns.barplot(x=tactics_counts.index, y=tactics_counts.values)
plt.title('Distribution of MITRE Tactics in Detected Anomalies')
plt.ylabel('Frequency')
plt.xlabel('MITRE Tactics')
plt.xticks(rotation=45)
plt.show()

import openai

def get_explanation_from_gpt(anomaly_description):
    prompt = f"Hey, explain the following anomaly like you're talking to a friend. Use simple, everyday language and give real-world examples so it's easy to understand: {anomaly_description}"
    
    response = openai.Completion.create(
        engine="text-davinci-003",  
        prompt=prompt,
        max_tokens=100,
        temperature=0.7 
    )
    
    return response.choices[0].text.strip()

anomaly_description = "Detected suspicious exfiltration of data to IP 192.168.1.1 over TCP port 443. The flow lasted for 2 minutes with consistent packet intervals.
explanation = get_explanation_from_gpt(anomaly_description)
print(explanation)

prompt = f"Explain the following anomaly like you're talking to a friend, but use funny analogies and everyday examples to make it super easy to understand: {anomaly_description}"

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest

st.title("Anomaly Detection and Traffic Analysis")
uploaded_file = st.file_uploader("Upload Traffic Data CSV", type=["csv"])

if uploaded_file is not None:
  
    df = pd.read_csv(uploaded_file, encoding='ISO-8859-1', on_bad_lines='skip')
    st.write("Dataset loaded successfully!")
    st.write(df.head())
    df.columns = df.columns.str.strip()
    df = df.dropna()
    X = df.drop(columns=['Label'])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)

    iso_forest = IsolationForest(n_estimators=100, contamination=0.1)
    iso_forest.fit(X_pca)
    predictions = iso_forest.predict(X_pca)
    predictions = [0 if x == 1 else 1 for x in predictions]
    df['Anomaly'] = predictions
    st.write("Anomaly Detection Results:", df[['Label', 'Anomaly']].head())
    plt.figure(figsize=(10, 6))
    sns.scatterplot(x=X_pca[:, 0], y=X_pca[:, 1], hue=df['Anomaly'], palette={0: 'green', 1: 'red'})
    st.pyplot()

    if st.button("Generate Explanations"):
        for index, row in df.iterrows():
            explanation = generate_explanation(row)
            st.write(f"Anomaly {index + 1}: {explanation}")

def generate_explanation(row):
  
    anomaly_details = f"Detected suspicious activity. The flow lasted {row['Flow Duration']} seconds, from IP {row['Source IP']} to IP {row['Destination IP']}. The traffic used port {row['Destination Port']}. The anomaly was detected due to irregular patterns."
    prompt = f"Explain the anomaly detected with the following details: {anomaly_details}"
    explanation = call_gpt(prompt)
    return explanation

def call_gpt(prompt):
    import openai
    openai.api_key = "your_openai_api_key"
    
    response = openai.Completion.create(
        engine="text-davinci-003",  # Or another available model
        prompt=prompt,
        max_tokens=150
    )
    
    return response.choices[0].text.strip()

import streamlit as st

mode = st.radio('Choose Your Theme', ['Dark Mode', 'Pink Mode'])

if mode == 'Dark Mode':
    st.set_page_config(page_title="AI Threat Hunter", page_icon=":guardsman:", layout="wide", initial_sidebar_state="expanded")
    st.markdown(
        """
        <style>
        .css-1v0mbdj {background-color: #0E1117;}
        .css-1v0mbdj h1 {color: white;}
        </style>
        """,
        unsafe_allow_html=True,
    )
else:
    st.set_page_config(page_title="AI Threat Hunter", page_icon=":guardsman:", layout="wide", initial_sidebar_state="expanded")
    st.markdown(
        """
        <style>
        .css-1v0mbdj {background-color: #F1D1D6;}
        .css-1v0mbdj h1 {color: #D84B8E;}
        </style>
        """,
        unsafe_allow_html=True,
    )

st.image("https://media.giphy.com/media/xT0BKhV5sN2v0Q3v4Y/giphy.gif", use_column_width=True)
st.markdown(
    '<h1 style="font-family:sans-serif; color:#D84B8E;">🌸 AI Threat Hunter 🌸</h1>',
    unsafe_allow_html=True
)

import streamlit as st

if st.button('Switch to Pink Mode'):
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #FFCCFF;
            color: #333333;
        }
        .stButton>button {
            background-color: #FF4B4B;
            color: white;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

st.title("AI Threat Hunter Dashboard")

import streamlit as st
import pandas as pd
csv = df.to_csv(index=False).encode('utf-8')
st.download_button("Download CSV", csv, "output.csv", "text/csv", key='download-csv')
import pandas as pd

df = pd.read_csv("ai_threat_hunter_results.csv")
print(df.head())

