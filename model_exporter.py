import numpy as np
import pandas as pd
import json
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split

# This script exports your trained model to a format usable by the browser extension

# Load the dataset
data = pd.read_csv("phishing.csv")
data = data.drop(['Index'], axis=1)

# Split features and target
X = data.drop(["class"], axis=1)
y = data["class"]

# Get feature names
feature_names = X.columns.tolist()

# Train the model with the same parameters as your original code
gbc = GradientBoostingClassifier(max_depth=4, learning_rate=0.7)
gbc.fit(X, y)

# Extract feature importances
feature_importances = gbc.feature_importances_

# Create a dictionary of feature names and their corresponding importance values
model_coefficients = {}
for feature, importance in zip(feature_names, feature_importances):
    model_coefficients[feature] = float(importance)

# Save the model coefficients to a JSON file
with open('model_coefficients.json', 'w') as f:
    json.dump(model_coefficients, f, indent=2)

# Create a simple JavaScript file that can be included in the extension
js_output = "// Auto-generated model coefficients\nconst MODEL_COEFFICIENTS = " + json.dumps(model_coefficients, indent=2) + ";\n"

with open('model_data.js', 'w') as f:
    f.write(js_output)

print("Model exported successfully!")
print(f"Feature names: {feature_names}")
print(f"Total features: {len(feature_names)}")

# For demonstration, let's show the top 5 most important features
sorted_features = sorted(zip(feature_names, feature_importances), key=lambda x: x[1], reverse=True)
print("\nTop 5 most important features:")
for feature, importance in sorted_features[:5]:
    print(f"- {feature}: {importance:.4f}")

# Optional: Export a simple decision function for JavaScript implementation
# This is a simplified version that won't match GBC exactly but gives a starting point
def export_simple_decision_function():
    # Get the first tree as an example
    first_tree = gbc.estimators_[0, 0]
    
    # This is a very simplified approach - in reality, you'd need to export the entire ensemble
    tree_structure = {
        "nodes": []
    }
    
    # Function to recursively extract tree nodes
    def extract_tree(tree, node_id=0):
        if tree.children_left[node_id] == -1:  # Leaf node
            return {
                "type": "leaf",
                "value": float(tree.value[node_id][0][0])
            }
        else:
            return {
                "type": "split",
                "feature": feature_names[tree.feature[node_id]],
                "threshold": float(tree.threshold[node_id]),
                "left": extract_tree(tree, tree.children_left[node_id]),
                "right": extract_tree(tree, tree.children_right[node_id])
            }
    
    # Extract the first few levels of the tree
    tree_structure = extract_tree(first_tree)
    
    with open('simple_tree.json', 'w') as f:
        json.dump(tree_structure, f, indent=2)
    
    print("\nExported a simplified decision tree to simple_tree.json")

# Uncomment to export a simplified decision tree
# export_simple_decision_function()