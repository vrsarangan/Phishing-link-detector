# Phishing-link-detector
- Redirect Handling: The follow_redirects function follows URL redirects to determine the final URL and its HTTP status code.
- Blacklist Check: The check_blacklist function checks if the final URL domain is in a predefined phishing blacklist.
- Heuristic Checks: The detect_phishing function uses regular expressions to look for common phishing indicators in the final URL.
- Machine Learning: The script trains a Naive Bayes model using a small dataset and integrates it into the phishing detection process. The detect_phishing_ml 
 function uses this model to predict whether the URL is phishing based on its features.
Usage Note:
- The sample data for the machine learning model is very small. For better accuracy, expand the dataset with more phishing and legitimate URLs.
- The blacklist can be updated with more known phishing domains or integrated with an online service that provides real-time phishing domain lists.
- Run the script and enter a URL when prompted to analyze it for potential phishing indicators. The output will indicate whether phishing is detected.
- This script provides a comprehensive phishing detection solution that combines multiple layers of analysis for improved accuracy.
