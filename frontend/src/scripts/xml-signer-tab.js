import { SOCKET_URL, SAMPLE_LOGO } from './constants.js';

export default () => ({

    // Form data properties for two-way binding
    allowedStorages: ["JKS", "PKCS12"],
    webSocket: null,
    response: null,
    callback: null,
    activeSubTab: 'xml',
    signatureType: 'xml',
    isArray: false,
    dataToSign: `\
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<root>
    <item>Сәлем, досым! Привет, друг!</item>
    <note>Бұл тест. Это тест.</note>
</root>`,
    decode: 'false',
    encapsulate: 'true',
    digested: 'false',
    tsaProfile: false,
    isAllowExpired: true,
    isAllowRevoked: true,
    isOutputCert: true,
    iin: '123456789012',
    bin: '012345678912',
    serialNumber: '',
    extKeyUsageOids: '',
    buildChain: false,
    caCerts: '',
    signature: '',

    // WebSocket heartbeat and logging
    isConnected: false,
    heartbeatInterval: null,
    lastHeartbeat: null,
    logs: [],
    maxLogs: 100,
    signingResolve: null,

    init() {
        this.connect();
    },

    connect() {
        if (this.webSocket && this.webSocket.readyState < 2) {
            console.log(`reusing the socket connection [state = ${this.webSocket.readyState}]: ${this.webSocket.url}`);
            return Promise.resolve(this.webSocket);
        }

        return new Promise((resolve, reject) => {
            try {
                this.webSocket = new WebSocket(SOCKET_URL);
            } catch (error) {
                this.isSigning = false;
                console.error('Failed to create WebSocket connection:', error);
                this.errorMessage = 'Failed to establish connection. Please check your network.';
                reject(error);
                return;
            }

            this.webSocket.onopen = () => {
                console.log(`socket connection is opened [state = ${this.webSocket.readyState}]: ${this.webSocket.url}`);
                this.isConnected = true;
                // Send initial handshake
                const initialMessage = { module: "nca", version: "2.3" };
                this.webSocket.send(JSON.stringify(initialMessage));
                this.logMessage('sent', initialMessage);
                this.webSocket.onmessage = this.handleMessage.bind(this);
                this.startHeartbeat();
                resolve(this.webSocket);
            };

            this.webSocket.onerror = (err) => {
                this.isSigning = false;
                console.error('socket connection error : ', err);
                this.errorMessage = 'Connection failed. Please ensure NCALayer is running and try again.';
                reject(err);
            };

            this.webSocket.onclose = (event) => {
                console.log(`WebSocket closed. Code: ${event.code}, Reason: ${event.reason}, Clean: ${event.wasClean}`);
                this.isConnected = false;
                this.stopHeartbeat();
                if (!event.wasClean && event.code !== 1000) {
                    this.errorMessage = 'Connection lost unexpectedly. Please try again.';
                    this.openDialog();
                }
            };

            // Add timeout for connection
            setTimeout(() => {
                if (this.webSocket.readyState === WebSocket.CONNECTING) {
                    this.webSocket.close();
                    this.isSigning = false;
                    this.errorMessage = 'Connection timeout. Please check if NCALayer is running.';
                    reject(new Error('Connection timeout'));
                }
            }, 10000); // 10 second timeout
        });
    },

    async request() {
        this.isSigning = true;
        this.errorMessage = '';
        this.successMessage = '';

        const selectedStorages = this.allowedStorages.filter(storage => storage); // Filter out empty values
        const signatureType = this.signatureType;
        let dataToSign = this.dataToSign;

        if (this.isArray) {
            dataToSign = [dataToSign];
        }

        const decode = this.decode === 'true';
        const encapsulate = this.encapsulate === 'true';
        const digested = this.digested === 'true';

        const extKeyUsageOidString = this.extKeyUsageOids;
        const extKeyUsageOids = extKeyUsageOidString ? extKeyUsageOidString.split(',').map(s => s.trim()) : [];

        const caCertsString = this.caCerts;
        let caCerts;
        if (this.buildChain) {
            caCerts = caCertsString ? caCertsString.split(',').map(s => s.trim()) : null;
        } else {
            caCerts = null;
        }

        const localeRadio = localStorage.getItem('locale');

        let tsaProfile = null;
        if (this.tsaProfile) {
            tsaProfile = {};
        }

        const iin = this.iin;
        const bin = this.bin;
        const serialNumber = this.serialNumber;

        const signInfo = {
            module: 'kz.gov.pki.knca.basics',
            method: 'sign',
            args: {
                allowedStorages: selectedStorages,
                format: signatureType,
                data: dataToSign,
                signingParams: { decode, encapsulate, digested, tsaProfile },
                signerParams: {
                    extKeyUsageOids,
                    iin,
                    bin,
                    serialNumber,
                    chain: caCerts
                },
                locale: localeRadio
            }
        };

        signInfo.args.logo = SAMPLE_LOGO;

        if (this.isAllowExpired) {
            signInfo.args.signingParams.allowExpired = true;
        }

        if (this.isAllowRevoked) {
            signInfo.args.signingParams.allowRevoked = true;
        }

        if (this.isOutputCert) {
            signInfo.args.signingParams.outputCert = true;
        }

        if (selectedStorages.length === 0) {
            delete signInfo.args.allowedStorages;
        }

        return this.connect().then((webSocket) => {
            this.logMessage('sent', signInfo);
            webSocket.send(JSON.stringify(signInfo));

            return new Promise((resolve) => {
                this.signingResolve = resolve;
            });
        }).catch((err) => {
            this.isSigning = false;
            console.error('Signing request failed:', err);
            this.errorMessage = 'An error occurred during signing. Please check the console for details.';
        });
    },

    async sign() {
        // Clear previous messages
        this.errorMessage = '';
        this.successMessage = '';

        // Validation
//        if (!this.iin || this.iin.length !== 12) {
//            this.errorMessage = 'IIN must be exactly 12 digits';
//            return;
//        }
//        if (!this.bin || this.bin.length !== 12) {
//            this.errorMessage = 'BIN must be exactly 12 digits';
//            return;
//        }
        if (!this.dataToSign.trim()) {
            this.errorMessage = 'Data to sign cannot be empty';
            return;
        }
        const selectedStorages = this.allowedStorages.filter(storage => storage);
        if (selectedStorages.length === 0) {
            this.errorMessage = 'At least one storage must be selected';
            return;
        }

        await this.request();
    },

    resetForm() {
        this.allowedStorages = ["JKS", "PKCS12"];
        this.isSigning = false;
        this.errorMessage = '';
        this.successMessage = '';
        this.activeSubTab = 'xml';
        this.signatureType = 'xml';
        this.isArray = false;
        this.dataToSign = '';
        this.decode = 'false';
        this.encapsulate = 'true';
        this.digested = 'false';
        this.tsaProfile = false;
        this.isAllowExpired = true;
        this.isAllowRevoked = true;
        this.isOutputCert = true;
        this.iin = '123456789012';
        this.bin = '012345678912';
        this.serialNumber = '';
        this.extKeyUsageOids = '';
        this.buildChain = false;
        this.caCerts = '';
        this.signature = '';
    },

    copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                this.successMessage = 'Signature copied to clipboard!';
                setTimeout(() => this.successMessage = '', 3000);
            }).catch(() => {
                this.fallbackCopyToClipboard(text);
            });
        } else {
            this.fallbackCopyToClipboard(text);
        }
    },

    fallbackCopyToClipboard(text) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            this.successMessage = 'Signature copied to clipboard!';
            setTimeout(() => this.successMessage = '', 3000);
        } catch (err) {
            this.errorMessage = 'Failed to copy signature to clipboard';
        }
        document.body.removeChild(textArea);
    },

    openDialog() {
        if (confirm(this.translate('connectionError'))) {
            location.reload();
        }
    },

    loadCaPem(event) {
        const file = event.target.files[0];
        if (file) {
            this.buildChain = true;
            file.text().then(text => {
                this.caCerts = text;
            });
        }
    },

    init() {
        this.$watch('activeSubTab', (value) => {
            this.signatureType = value;
        });
    },

    startHeartbeat() {
        this.stopHeartbeat(); // Clear any existing interval
        this.heartbeatInterval = setInterval(() => {
            if (this.webSocket && this.webSocket.readyState === WebSocket.OPEN) {
                this.lastHeartbeat = Date.now();
                this.webSocket.send(JSON.stringify({ type: 'ping' }));
                this.logMessage('sent', { type: 'ping' });
            }
        }, 30000); // Ping every 30 seconds
    },

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    },

    logMessage(direction, message) {
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = {
            timestamp,
            direction, // 'sent' or 'received'
            message: typeof message === 'string' ? message : JSON.stringify(message, null, 2)
        };
        this.logs.unshift(logEntry); // Add to beginning for latest first
        if (this.logs.length > this.maxLogs) {
            this.logs = this.logs.slice(0, this.maxLogs);
        }
    },

    handleMessage(event) {
        const data = event.data;
        this.logMessage('received', data);
        const parsed = JSON.parse(data);
        if (parsed.status !== undefined) {
            // This is a signing response
            this.response = parsed;
            if (parsed.status === true) {
                const responseBody = parsed.body;
                if (responseBody != null) {
                    this.isSigning = false;
                    if (responseBody.hasOwnProperty('result')) {
                        const result = responseBody.result;
                        if (result.hasOwnProperty('signatures')) {
                            const signatures = result.signatures;
                            const certificate = result.certificate;
                            this.signature = `${signatures}\n${certificate}`;
                        } else {
                            this.signature = result;
                        }
                        this.successMessage = 'Signature generated successfully!';
                    }
                }
            } else if (parsed.status === false) {
                this.isSigning = false;
                const responseCode = parsed.code;
                this.errorMessage = `Signing failed: ${responseCode}`;
            }
            if (this.signingResolve) {
                this.signingResolve(parsed);
                this.signingResolve = null;
            }
        }
        // Other messages (initial response, pong) are just logged
    },

    translate(key) {
        return window.knca.translator.t(key);
    }
});
