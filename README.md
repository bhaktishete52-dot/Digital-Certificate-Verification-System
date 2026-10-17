# Digital Certificate Verification System

A web-based application for issuing, managing, and verifying student certificates.

## Features

- Administrator login and authentication
- Certificate issuance with unique certificate IDs
- Certificate verification
- Active and revoked certificate status
- Certificate revocation
- Audit logging
- SQLite database integration
- Input validation and CSRF protection

## Technologies Used

- Python
- Flask
- SQLite
- HTML
- CSS

## Installation and Setup

1. Clone this repository:

   ```bash
   git clone YOUR_REPOSITORY_URL
   ```

2. Open the project folder:

   ```bash
   cd DigitalCertificateVerification
   ```

3. Create a virtual environment:

   ```bash
   python -m venv venv
   ```

4. Activate it on Windows:

   ```bash
   venv\Scripts\activate
   ```

5. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

6. Configure a strong secret key using an environment variable before running the application.

7. Start the application:

   ```bash
   python app.py
   ```

8. Open `http://127.0.0.1:5000/` in your browser.

## Security Note

This project is an academic prototype. Certificate verification checks database records and does not independently verify a cryptographic digital signature. Configure secure administrator credentials and production settings before deployment.

## Author

Bhakti Shivaji Shete

## License

Add a license if you intend to distribute the project under specific reuse terms.