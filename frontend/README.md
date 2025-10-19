# frontend

An example web application for testing NCALayer functionality. NCALayer is a digital signature tool used in Kazakhstan
for electronic document signing. This project demonstrates how to integrate with NCALayer via WebSocket to perform
signing operations.

## Features

- **Digital Signing**: Sign XML, CMS, or raw data using various storage types (e.g., AKKaztokenStore, AKKZIDCardStore,
  PKCS12, etc.)
- **Flexible Parameters**: Configure signing parameters like decode, encapsulate, digested, and more
- **Signer Filtering**: Filter signers by IIN, BIN, serial number, and extended key usage OIDs
- **Certificate Chain Building**: Optionally build certificate chains with custom CA certificates
- **Multilingual Support**: Interface available in Kazakh (Қазақша) and Russian (Русский)
- **Real-time Connection**: Connects to NCALayer via WebSocket at `wss://127.0.0.1:13579/`

## Prerequisites

- Node.js (version 14 or higher)
- NCALayer application installed and running on the local machine
- A compatible digital certificate and storage device (e.g., eToken, smart card)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/gleb619/knca-signer.git
   cd knca-signer/frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

## Usage

1. Start the development server:
   ```bash
   npm run serve
   ```

2. Open your browser and navigate to `http://localhost:3000` (or the port shown in the terminal).

3. Configure the signing parameters in the form:
    - Select allowed storage types
    - Choose signature format (xml, cms, or raw)
    - Enter data to sign
    - Adjust signing parameters (decode, encapsulate, etc.)
    - Optionally filter signers by IIN, BIN, or serial number
    - Set extended key usage OIDs

4. Click "Подписать" (Sign) to initiate the signing process.

5. NCALayer will open a dialog for certificate selection and PIN entry.

6. The signed data will be displayed in the signature textarea.

## Building for Production

To build the project for production:

```bash
npm run build
```

The built files will be in the `dist` directory.

To preview the production build:

```bash
npm run preview
```

## Testing

Run the test suite:

```bash
npm test
```

## Project Structure

- `index.html`: Main HTML file with the application UI
- `src/app.js`: Alpine.js application logic, including WebSocket communication and form handling
- `src/ncalayer.js`: Entry point that initializes Alpine.js
- `css/`: Stylesheets (Bootstrap and custom styles)
- `public/`: Static assets
- `tests/`: Test files (using Vitest)

## Dependencies

- **Alpine.js**: Lightweight JavaScript framework for reactive UI
- **Bootstrap**: CSS framework for styling
- **Vite**: Build tool and development server
- **Vitest**: Testing framework

