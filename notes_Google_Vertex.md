# Google Vertex AI Notes

These steps will help you obtain the `vertex_auth.json`

1. Go to Google Cloud Console
   - Navigate to https://console.cloud.google.com/

2. Create or Select a Project
   - Create a new project or select an existing project
   - Note the Project ID and put it in the VERTEX_PROJECT_ID variable in .env file

3. Enable Vertex AI API
   - Go to "APIs & Services"
   - Click "Enable APIs and Services"
   - Search for "Vertex AI API"
   - Click "Enable"

4. Create Service Account
   - Go to "IAM & Admin" > "Service Accounts"
   - Click "Create Service Account"
   - Enter a name (e.g., "vertex-ai-access")
   - Grant appropriate roles:
     - Vertex AI User
     - AI Platform Developer
     - Service Account User

5. Generate JSON Key
   - In the service account list, find your new account
   - Click "Keys" tab
   - Click "Add Key" > "Create new key"
   - Select JSON format
   - The key file will automatically download
   - Copy the json key to the `ai-gov-api` folder as `vertex_auth.json`

6. Secure the JSON File
   - Store in a secure location
   - Do not share or commit to version control
