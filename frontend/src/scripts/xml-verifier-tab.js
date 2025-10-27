export default () => ({
    activeSubTab: 'xml',

    // Form data for XML verification
    xmlContent: ``,
    xmlContentSample: `\
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<root>
	<item>Sample content to verify</item>
	<signature>Sample signature here</signature>
	<ds:Signature
		xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="">
				<ds:Transforms>
					<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
					<ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
				</ds:Transforms>
				<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
				<ds:DigestValue>b2458b13-78ab-4d9d-89aa-c20f0e1a79a2</ds:DigestValue>
			</ds:Reference>
		</ds:SignedInfo>
		<ds:SignatureValue>46f7e78c-bda5-44a9-a907-274aa1b0532e</ds:SignatureValue>
		<ds:KeyInfo>
			<ds:X509Data>
				<ds:X509Certificate>bfe57dc8-ed87-4f36-8496-ba566e02445e</ds:X509Certificate>
			</ds:X509Data>
		</ds:KeyInfo>
	</ds:Signature>
</root>`,
    xmlContentBase64: '',//TODO: add base64 example
    validationResult: null,
    isValidating: false,

    // Validation configuration
    validationConfig: {
        checkKalkanProvider: false,
        checkData: true,
        checkTime: true,
        checkIinInCert: false,
        checkIinInSign: false,
        checkBinInCert: false,
        checkBinInSign: false,
        checkCertificateChain: false,
        checkPublicKey: false,
        checkExtendedKeyUsage: false,
        extendedKeyUsageOids: '',
        expectedIin: '',
        expectedBin: ''
    },

    // File handling
    publicKeyFile: null,
    publicKeyFileName: '',

    // CA PEM file handling
    caPemFile: null,
    caPemFileName: '',

    initXmlVerifier() {
        //ignore
    },

    async handlePublicKeyFileChange(event) {
        const file = event.target.files[0];
        if (file) {
            this.publicKeyFileName = file.name;
            this.publicKeyFile = file;

            // Read file content as text
            const reader = new FileReader();
            reader.onload = (e) => {
                this.validationConfig.publicKey = e.target.result;
            };
            reader.readAsText(file);
        } else {
            this.publicKeyFileName = '';
            this.publicKeyFile = null;
            this.validationConfig.publicKey = '';
        }
    },

    async handleCaPemFileChange(event) {
        const file = event.target.files[0];
        if (file) {
            this.caPemFileName = file.name;
            this.caPemFile = file;

            // Read file content as text
            const reader = new FileReader();
            reader.onload = (e) => {
                this.validationConfig.caPem = e.target.result;
            };
            reader.readAsText(file);
        } else {
            this.caPemFileName = '';
            this.caPemFile = null;
            this.validationConfig.caPem = '';
        }
    },

    async validateXml() {
        // Validation
        if (!this.xmlContent || !this.xmlContent.trim()) {
            this.addNotification('error', 'xmlValidationRequired');
            return;
        }

        // Check if public key file is required but not provided
        if (this.validationConfig.checkPublicKey && (!this.validationConfig.publicKey || !this.validationConfig.publicKey.trim())) {
            this.addNotification('error', 'publicKeyRequired');
            return;
        }

        this.isValidating = true;

        try {
            const requestData = {
                xml: this.xmlContent.trim(),
                ...this.validationConfig
            };

            // Remove empty expectedIin and expectedBin
            if (!requestData.expectedIin.trim()) {
                delete requestData.expectedIin;
            }
            if (!requestData.expectedBin.trim()) {
                delete requestData.expectedBin;
            }

            // Certificate content sent as plain text (backend will handle parsing)

            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Validation failed');
            }

            this.validationResult = result;

            if (result.valid) {
                this.addNotification('success', this.translate(result.code || 'xmlVerificationPassed'));
            } else {
                this.addNotification('error', this.translate(result.code || 'xmlVerificationFailed'));
            }

        } catch (error) {
            console.error('XML validation error:', error);
            this.addNotification('error', this.translate(error.message || 'xmlVerificationFailedGeneral'));
        } finally {
            this.isValidating = false;
        }
    },

    resetValidation() {
        this.xmlContent = '';
        this.validationConfig.checkKalkanProvider = false;
        this.validationConfig.checkData = true;
        this.validationConfig.checkTime = true;
        this.validationConfig.checkIinInCert = false;
        this.validationConfig.checkIinInSign = false;
        this.validationConfig.checkBinInCert = false;
        this.validationConfig.checkBinInSign = false;
        this.validationConfig.checkCertificateChain = false;
        this.validationConfig.checkPublicKey = false;
        this.validationConfig.checkExtendedKeyUsage = false;
        this.validationConfig.extendedKeyUsageOids = '';
        this.validationConfig.expectedIin = '';
        this.validationConfig.expectedBin = '';
        // Reset certificate content
        this.validationConfig.publicKey = '';
        this.validationConfig.caPem = '';
        // Reset file inputs
        const publicKeyFileInput = document.getElementById('publicKeyFile');
        if (publicKeyFileInput) publicKeyFileInput.value = '';
        const caPemFileInput = document.getElementById('caPemFile');
        if (caPemFileInput) caPemFileInput.value = '';
        // Reset file properties
        this.publicKeyFile = null;
        this.publicKeyFileName = '';
        this.caPemFile = null;
        this.caPemFileName = '';
        this.validationResult = null;
    },

    copyValidationResult() {
        if (!this.validationResult) return;

        // Create a formatted string with validation details
        let resultText = JSON.stringify(this.validationResult, null, 2);

        // Try modern clipboard API first
        if (navigator.clipboard) {
            navigator.clipboard.writeText(resultText).then(() => {
                this.addNotification('success', 'copySuccess');
            }).catch(() => {
                this.fallbackCopyValidationResult(resultText);
            });
        } else {
            this.fallbackCopyValidationResult(resultText);
        }
    },

    fallbackCopyValidationResult(text) {
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
            this.addNotification('success', 'copySuccess');
        } catch (err) {
            this.addNotification('error', 'copyFailed');
        }
        document.body.removeChild(textArea);
    },

    handleSignatureVerify(signature) {
        this.xmlContent = signature?.signature || 'N/A';
    },

    async handleCertificateSelection(detail) {
        const { userCert, legalCert, caCert } = detail;
        const cert = { ...userCert, ...legalCert };

        // Pre-fill expected values from selected certificate
        if (cert.iin != null && cert.iin !== '') {
            this.validationConfig.expectedIin = cert.iin;
            this.validationConfig.checkIinInCert = true;
            this.validationConfig.checkIinInSign = true;
        }
        if (cert.bin != null && cert.bin !== '') {
            this.validationConfig.expectedBin = cert.bin;
            this.validationConfig.checkBinInCert = true;
            this.validationConfig.checkBinInSign = true;
        }

        // Pre-fill CA certificate PEM for chain validation
        if (caCert && typeof window !== 'undefined' && window.Alpine && window.Alpine.store) {
            const certificateStore = window.Alpine.store('certificateStore');
            if (certificateStore && certificateStore.fetchCaCert) {
                try {
                    const pem = await certificateStore.fetchCaCert();
                    if (pem) {
                        this.validationConfig.caPem = pem;
                        this.validationConfig.checkCertificateChain = true;
                    }
                } catch (error) {
                    console.warn('Failed to fetch CA certificate:', error);
                }
            }
        }
    },

    // Helper functions for enhanced UI

    getDetailCardClasses(detail) {
        const statusClasses = {
            passed: 'border-green-200 bg-green-50',
            failed: 'border-red-200 bg-red-50',
            'not_found': 'border-yellow-200 bg-yellow-50',
            error: 'border-orange-200 bg-orange-50'
        };
        return statusClasses[detail.status] || 'border-gray-200 bg-gray-50';
    },

    getStatusIcon(status) {
        const icons = {
            passed: '<svg class="w-4 h-4 text-green-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>',
            failed: '<svg class="w-4 h-4 text-red-600" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="nonzero" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"></path></svg>',
            'not_found': '<svg class="w-4 h-4 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path></svg>',
            error: '<svg class="w-4 h-4 text-orange-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path></svg>'
        };
        return icons[status] || icons.error;
    },

    getDetailTitle(detail) {
        const titles = {
            signature: 'checkDataIntegrity',
            kalkanProvider: 'checkKalkanProvider',
            dataIntegrity: 'checkDataIntegrity',
            timestamp: 'checkTimestamp',
            certificateIin: 'checkIinCertificate',
            signatureIin: 'checkIinSignature',
            certificateBin: 'checkBinCertificate',
            signatureBin: 'checkBinSignature',
            certificateChain: 'checkCertificateChain',
            publicKey: 'checkPublicKeyMatch',
            extendedKeyUsage: 'checkExtendedKeyUsage',
            general: 'Validation'
        };
        return this.translate(titles[detail.key] || detail.key);
    },

    getStatusBadgeClasses(status) {
        const classes = {
            passed: 'bg-green-100 text-green-800',
            failed: 'bg-red-100 text-red-800',
            'not_found': 'bg-yellow-100 text-yellow-800',
            error: 'bg-orange-100 text-orange-800'
        };
        return classes[status] || classes.error;
    },

    getStatusText(status) {
        const texts = {
            passed: 'validationStatusPassed',
            failed: 'validationStatusFailed',
            'not_found': 'validationStatusNotFound',
            error: 'validationStatusError'
        };
        return this.translate(texts[status] || texts.error);
    },

    getStatusCount(status) {
        if (!this.validationResult?.details) return 0;
        return this.validationResult.details.filter(detail => detail.status === status).length;
    },

    hasErrors() {
        return this.getStatusCount('error') > 0;
    }

});
