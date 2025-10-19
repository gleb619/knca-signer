import './css/style.scss';

import Alpine from 'alpinejs';
import morph from '@alpinejs/morph';
import htmx from 'htmx.org';

import { Translator } from '@owja/i18n';
import kk from "./i18n/kk.json";
import ru from "./i18n/ru.json";

window.htmx = htmx;
window.Alpine = Alpine;
window.knca = {
    translator: new Translator({ default:"kk", fallback:"ru" })
};

window.knca.translator.addResource("kk", kk);
window.knca.translator.addResource("ru", ru);

import 'htmx-ext-alpine-morph';

import kncaApp from './scripts/app.js';
import xmlSignerTab from './scripts/xml-signer-tab.js';
import certificatorTab from './scripts/certificator-tab.js';
import xmlVerifierTab from './scripts/xml-verifier-tab.js';
import appStoreTab from './scripts/app-store.js';

// Register Alpine components immediately
Alpine.store('certificateStore', appStoreTab)
Alpine.data('kncaApp', kncaApp);
Alpine.data('xmlSignerTab', xmlSignerTab);
Alpine.data('certificatorTab', certificatorTab);
Alpine.data('xmlVerifierTab', xmlVerifierTab);

// Configure HTMX for Alpine.js integration
document.addEventListener('DOMContentLoaded', () => {
    
    // Initialize HTMX extensions
    if (window.htmx) {
        // Configure Alpine Morph extension
        //htmx.config.globalViewTransitions = true;

        let intervalId;
        let retryCount = 0;
        const MAX_RETRIES = 3;

        // Add HTMX event listener to reinitialize Alpine components after swaps
        document.addEventListener('htmx:afterSwap', (evt) => {
            // Re-initialize Alpine on HTMX content swaps with improved timing and validation
            if (window.Alpine && evt.detail.target) {
                // Wait longer for data to settle, with multiple attempts

                setTimeout(() => {
//                    window.Alpine.initTree(evt.detail.target);
//                    htmx.process(evt.detail.target);

                    // Clear previous interval if exists
                    if (intervalId) {
                        clearInterval(intervalId);
                        retryCount = 0; // Reset retry count for a new swap
                    }

                    // Execute only once
                    intervalId = setInterval(() => {
                        if (retryCount < MAX_RETRIES) {
                            document.querySelectorAll('[hx-get]').forEach(el => {
                                htmx.process(el);
                                htmx.trigger(el, 'lateLoad');
                            });
                            retryCount++;
                        } else {
                            clearInterval(intervalId); // Stop the interval after MAX_RETRIES
                            intervalId = null; // Clear the intervalId
                            console.warn('Htmx lateLoad interval stopped after maximum retries.');
                        }
                    }, 300);

                }, 100);
            }

        });
    }

    // Initialize certificate store on page load
    setTimeout(() => {
        // Load saved certificate selection if it exists
        document.dispatchEvent(new CustomEvent('app-started'));
    }, 500);
});

Alpine.plugin(morph);
Alpine.start();

const element = document.querySelector('[x-data="kncaApp"]');
if(element) {
    element.style.removeProperty('display');
}
