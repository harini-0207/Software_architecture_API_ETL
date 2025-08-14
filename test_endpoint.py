import requests

def test_threatfox_connection():
    url = "https://threatfox.abuse.ch/export/json/recent/"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        print("Testing connection to:", url)
        response = requests.get(url, headers=headers, timeout=30)
        print("Status Code:", response.status_code)
        
        if response.status_code == 200:
            print("Success! First 200 chars of response:")
            print(response.text[:200])
            
            try:
                data = response.json()
                print("\nJSON structure keys:", data.keys())
                if 'data' in data:
                    print("Found 'data' key with", len(data['data']), "items")
                else:
                    print("No 'data' key found in response")
            except ValueError as e:
                print("Failed to parse JSON:", e)
        else:
            print("Request failed with status:", response.status_code)
            
    except Exception as e:
        print("Connection test failed:", str(e))

if __name__ == "__main__":
    test_threatfox_connection()