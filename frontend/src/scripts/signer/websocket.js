import { SOCKET_URL } from '../constants.js';
export default {
    webSocket: null,
    response: null,
    callback: null,
    isConnected: false,
    heartbeatInterval: null,
    lastHeartbeat: null,
    logs: [],
    maxLogs: 100,
    signingResolve: null,

    initWebSocket() {
        this.connect(false).then((webSocket) => {
            console.info("Connected to websocket");
        }).catch((err) => {
            console.error('Can\'t connect to websocket', err);
        });
    },

    connect(shouldOpenDialog = true) {
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
                this.addNotification('error', 'Failed to establish connection. Please check your network.');
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
                this.addNotification('error', 'Connection failed. Please ensure NCALayer is running and try again.');
                reject(err);
            };

            this.webSocket.onclose = (event) => {
                console.log(`WebSocket closed. Code: ${event.code}, Reason: ${event.reason}, Clean: ${event.wasClean}`);
                this.isConnected = false;
                this.stopHeartbeat();
                if (!event.wasClean && event.code !== 1000) {
                    this.addNotification('error', 'WebSocket connection lost unexpectedly. Please try again.');
                    if(shouldOpenDialog) {
                        this.openDialog();
                    }
                }
            };

            // Add timeout for connection
            setTimeout(() => {
                if (this.webSocket.readyState === WebSocket.CONNECTING) {
                    this.webSocket.close();
                    this.isSigning = false;
                    this.addNotification('error', 'Connection timeout. Please check if NCALayer is running.');
                    reject(new Error('Connection timeout'));
                }
            }, 10000); // 10 second timeout
        });
    },

    startHeartbeat() {
        this.stopHeartbeat(); // Clear any existing interval
        this.heartbeatInterval = setInterval(() => {
            if (this.webSocket && this.webSocket.readyState === WebSocket.OPEN) {
                this.lastHeartbeat = Date.now();
                this.webSocket.send('--heartbeat--');

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

    logMessage(direction, message_) {
        const timestamp = new Date().toLocaleTimeString();
        try {
            const message = typeof message_ === 'string' ? JSON.parse(message_) : message_
            const logEntry = {
                timestamp,
                direction, // 'sent' or 'received'
                message: JSON.stringify(message, null, 2),
                success: message.success ?? true
            };
            this.logs.unshift(logEntry); // Add to beginning for latest first
            if (this.logs.length > this.maxLogs) {
                this.logs = this.logs.slice(0, this.maxLogs);
            }
        }
        catch (e) {
            console.error(`LOG_ERROR: message=${message_};`, e);
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
                this.addNotification('error', `Signing failed: ${responseCode}`);
            }
            if (this.signingResolve) {
                this.signingResolve(parsed);
                this.signingResolve = null;
            }
        }
        // Other messages (initial response, pong) are just logged
    },
};
