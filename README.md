  
# An enhanced MQTT Communication Protocol for Privacy Preservation in Industrial Internet of Things (IIot) Systems
A secure and user-friendly MQTT-based communication system for Industrial IoT (IIoT), built with Python. This project implements AES encryption, OTP-based authentication, role-based access control (RBAC), GUI interfaces, and audit logging, making it ideal for secure IIoT deployments. This system supports both publishers and subscribers with individualized login interfaces.
## 🔐 Features
1.	Secure User Login and Registration  

2.	AES Encryption (CBC Mode)  

3.	Role-Based Access Control (RBAC)  

4.	MQTT Publish & Subscribe (via Mosquitto)

5.	Audit Logging for login and message events

6.	Tkinter GUI Interface for both publisher and subscriber interfaces

## 🧰 Technologies Used
1.	Python 3.x  

2.	Tkinter (GUI)


3.	paho-mqtt – MQTT client for Python

4.	pycryptodome – AES encryption/decryption


5.	bcrypt – Password hashing

6.	JSON, base64, os, hmac, hashlib – (standard libraries)


7.	**Mosquitto MQTT Broker** – For secure local message exchange

8.	**MQTT Explorer** – Visual monitoring and testing of MQTT topics  
   ([mqtt-explorer.com](https://mqtt-explorer.com))
   
## 🗂️ Project Structure

secure-mqtt-iiot/
├── publisher.py          # GUI-based login and AES-ecrypted MQTT message publisher
├── subscriber.py         # GUI-based login and  AES-decrypted MQTT message subscriber
├── users.json            # User database with roles
├── publisher_audit.log   # Logs login and publishing activity
├── subscriber_audit.log  # Login and subscription activity
├── requirements.txt      # Dependency list
├── README.md             # Project description and setup guide


## ⚙️ Setup Instructions
1. Clone the repository:
git clone https://github.com/Chiomaekeh/secure-mqtt-iiot.git 
cd secure-mqtt-iiot

2. Install required dependencies:
pip install -r requirements.txt

3. Start the Mosquitto broker (must be installed):

mosquitto

4. Run the publisher or subscriber:
1.	python publisher.py
2.	python subscriber.py

5. (Optional) Use MQTT Explorer to visualize messages and monitor topics in real time.

📸 Screenshots

🔵 Publisher GUI

1.	Login Screen

2.	Sign-Up Screen

3.	OTP Verification

4.	Forgot Password

5.	Topic Selection & Encrypted Publishing

🟢 Subscriber GUI

1.	Login Screen

2.	Forgot Password

3.	OTP Verification

4.	Topic Selection & Decrypted Subscription

👤 Author
**Ekeh Chioma Goodness**  
MSc Student, Imo State University, Owerri (IMSU)  
Email: chiomaekeh96@gmail.com  
GitHub: ([github.com/Chiomaekeh](https://github.com/Chiomaekeh)) 

📜 License

This project is licensed under the MIT License.
See the LICENSE file for details.

## Contributions & Feedback
Pull requests are welcome. For significant changes, open an issue first to discuss what you'd like to change.

 
