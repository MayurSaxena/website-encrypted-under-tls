const pubkey_pem = window.atob("{{pubkey_b64}}");
const { fetch: originalFetch } = window; // store the original fetch method
let symmetricEncryptionKey = null;

/*****
 * UTILITY FUNCTIONS TO DEAL WITH ARRAY BUFFERS
******/

function str2ab(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
      bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function b64_to_ab(base64_string){
    return Uint8Array.from(atob(base64_string), c => c.charCodeAt(0));
}

function ab_to_b64(arrayBuffer){
    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)));
}

//This function takes a PEM and returns a binary DER
function parsePublicKey(pem) {
    // fetch the part of the PEM string between header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pem.substring(pemHeader.length, pem.length - pemFooter.length-1);
    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);
    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);
    return binaryDer
}
//This function takes an ECDH PEM and imports it for use with SubtleCrypto
function importECDHPublicKey(pem) {
    return window.crypto.subtle.importKey(
        "spki",
        parsePublicKey(pem),
        {name: "ECDH", namedCurve: "P-384"},
        true,
        []
    );
}

// This function takes a SubtleCrypto public key and turns it in to a PEM
async function exportPublicKey(key) {
    const exported = await window.crypto.subtle.exportKey(
      "spki",
      key
    );
    const pemExported = `-----BEGIN PUBLIC KEY-----\n${ab_to_b64(exported)}\n-----END PUBLIC KEY-----`;
    return pemExported;
}

// This function outputs a hex digest SHA-256 hash
async function hashMessage(message) {
    const msgUint8 = new TextEncoder().encode(message);                           // encode as (utf-8) Uint8Array
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);           // hash the message
    const hashArray = Array.from(new Uint8Array(hashBuffer));                     // convert buffer to byte array
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join(''); // convert bytes to hex string
    return hashHex;
}

// This function imports an RSA public PEM for signature verification
function importRsaVerificationKey(pem) {
    return window.crypto.subtle.importKey(
        "spki",
        parsePublicKey(pem),
        {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
        },
        true,
        ["verify"]
    );
}

// This function takes care of negotiating a symmetric key with the server
async function establishSharedEncryptionKey(ecdhKeypair, serverVerificationKey) {
    const ecdh_public_pem = await exportPublicKey(ecdhKeypair.publicKey)
    // Send ECDH public portion to server
    const r = await fetch("/establishkey", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        body: `public_key=${btoa(ecdh_public_pem)}` // base64 the PEM
    })

    const receivedData = await r.json()
    // response is a JSON blob with the server's public ECDH data and an encrypted signature
    const received_public_pem = atob(receivedData.public_key);
    const server_ecdh_pub = await importECDHPublicKey(received_public_pem);
    // derive the same 384 bit secret that the server generated
    const shared_secret = await window.crypto.subtle.deriveBits({ name: "ECDH", namedCurve: "P-384", public: server_ecdh_pub }, ecdhKeypair.privateKey, 384);
    // convert the raw 384 bits to a key that we can use with HKDF to generate an AES key (same as the server)
    const shared_secret_as_key = await window.crypto.subtle.importKey("raw",shared_secret, {name:"HKDF"},false, ["deriveKey", "deriveBits"])
    // Use HKDF to generate a 256-bit AES-CBC key. Note that the salt is the same one used on the server.
    const derived_key = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: str2ab("SaltySalt"), info: new Uint8Array([]) }, 
        shared_secret_as_key, 
        {
            name: "AES-CBC",
            length: 256
        },
        true,
        ["encrypt", "decrypt"]
    );
    
    // construct the message to be verified: "<SERVER_ECDH_PUBLIC_DATA_HASH>,<CLIENT_ECDH_PUBLIC_DATA_HASH>"
    const server_pem_hash = await hashMessage(received_public_pem);
    const client_pem_hash = await hashMessage(ecdh_public_pem);
    const message_to_verify = `${server_pem_hash},${client_pem_hash}`;
    
    // Decrypt using our generated AES key which should match the server's. Note the usage of the same IV.
    const dec = await window.crypto.subtle.decrypt({name: "AES-CBC", iv: str2ab('TheSixteenByteIV')},derived_key,b64_to_ab(receivedData.verification));
    // Verify the signature with the server's public RSA key
    const verification_result = await window.crypto.subtle.verify("RSASSA-PKCS1-v1_5", serverVerificationKey, str2ab(atob(ab2str(dec))), str2ab(message_to_verify));
    // Store the symmetric key in a global variable
    symmetricEncryptionKey = derived_key;
    return verification_result
}

// thanks to this dude https://stackoverflow.com/questions/17380744/replace-dom-with-javascript-and-run-new-scripts
// this function is required to run things in <script> tags after the DOM is written to.
// Not needed for key exchange at all, but is needed to load encrypted content.
function runScripts(element) {
    var list, scripts, index;

    // Get the scripts
    list = element.getElementsByTagName("script");
    scripts = [];
    for (index = 0; index < list.length; ++index) {
        scripts[index] = list[index];
    }
    list = undefined;

    // Run them in sequence
    continueLoading();

    function continueLoading() {
        var script, newscript;

        // While we have a script to load...
        while (scripts.length) {
            // Get it and remove it from the DOM
            script = scripts[0];
            script.parentNode.removeChild(script);
            scripts.splice(0, 1);

            // Create a replacement for it
            newscript = document.createElement('script');

            // External?
            if (script.src) {
                // Yes, we'll have to wait until it's loaded before continuing
                newscript.onerror = continueLoadingOnError;
                newscript.onload = continueLoadingOnLoad;
                newscript.onreadystatechange = continueLoadingOnReady;
                newscript.src = script.src;
            } else {
                // No, we can do it right away
                newscript.text = script.text;
            }

            // Start the script
            document.documentElement.appendChild(newscript);

            // If it's external, wait
            if (script.src) {
                return;
            }
        }

        // All scripts loaded
        newscript = undefined;

        // Callback on most browsers when a script is loaded

        function continueLoadingOnLoad() {
            // Defend against duplicate calls
            if (this === newscript) {
                continueLoading();
            }
        }

        // Callback on most browsers when a script fails to load

        function continueLoadingOnError() {
            // Defend against duplicate calls
            if (this === newscript) {
                continueLoading();
            }
        }

        // Callback on IE when a script's loading status changes

        function continueLoadingOnReady() {

            // Defend against duplicate calls and check whether the
            // script is complete (complete = loaded or error)
            if (this === newscript && this.readyState === "complete") {
                continueLoading();
            }
        }
    }
}

// This function returns a decrypted string
async function AESDecrypt(cipher_blob) {
    const dec_ab = await window.crypto.subtle.decrypt({name: "AES-CBC", iv: b64_to_ab(cipher_blob.iv)},
                                    symmetricEncryptionKey,
                                    b64_to_ab(cipher_blob.ciphertext))
    return ab2str(dec_ab);
}

// This function returns encryption data
async function AESEncrypt(msg) {
    //returns a cipher blob with iv and ciphertext
    const iv = await window.crypto.getRandomValues(new Uint8Array(16));
    const enc_ab = await window.crypto.subtle.encrypt({name: "AES-CBC", iv: iv},symmetricEncryptionKey,str2ab(msg));
    const cipher_blob = {iv: ab_to_b64(iv), ciphertext: ab_to_b64(enc_ab)}
    return JSON.stringify(cipher_blob);
}

// This function can be used to overwrite the whole DOM
// i.e. if the server is responding with <html>...</html>
function replaceFullDom(dom_text) {
    document.body.parentNode.innerHTML=dom_text;
    runScripts(document.documentElement);
}

// Simply queries a URL expecting <html>...</html> and overwrites the DOM
function loadContentFromURL(url, config=null) {
    fetch(url, config)
        .then((response) => response.text())
        .then((text) => replaceFullDom(text));
}


// Override the fetch method to account for encryption / decryption
window.fetch = async (...args) => {
    //https://blog.logrocket.com/intercepting-javascript-fetch-api-requests-responses/
    let [resource, config ] = args;
    // If we're sending data as part of a GET or POST
    if (config && config.body && symmetricEncryptionKey) {
        // replace with an encryption blob and hope the server is expecting an encrypted blob
        config.body = await AESEncrypt(config.body)
    }
    // do the fetch as usual
    const response = await originalFetch(resource, config);
    // if we have established a symmetric encryption key, then the response we're getting back is probably encrypted
    if (symmetricEncryptionKey) {
        // override the .text() method to decrypt the blob from the server using the symmetric key
        const decryptToText = () => response
                                    .clone()
                                    .json()
                                    .then((data) => AESDecrypt(data));
        response.text = decryptToText;
    }
    // return the response as usual
    return response;
};

// This code auto-runs once the window loads
window.addEventListener('load', async (event) => {
    if (localStorage.getItem("server_identity")) {
        const known_identity = localStorage.getItem("server_identity")
        if (known_identity !== pubkey_pem) {
            const trust_new_key = window.confirm("The server's public key has changed. You're probably being spied on. Press OK to trust this key or cancel to stop.")
            if (trust_new_key) {
                localStorage.setItem("server_identity", pubkey_pem);
            }
            else {
                throw Error("MITM ALERT!");
            }
            
        }
    }
    else {
        // Implicitly trust the key if we've never seen it before
        // Ideally we'd be able to give the user some details and ask them to confirm
        alert("Since this is your first time connecting, normally you would compare this identity certificate out-of-band. We'll pretend you did that.")
        localStorage.setItem("server_identity", pubkey_pem)
    }
    const serverVerificationKey = await importRsaVerificationKey(localStorage.getItem("server_identity"));
    const ecdhKeypair = await window.crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-384"}, true, ["deriveKey", "deriveBits"]);
    const negotiation_result = await establishSharedEncryptionKey(ecdhKeypair, serverVerificationKey)
    if (negotiation_result === true) {
        // get the encrypted blob and just overwrite the DOM
        loadContentFromURL("main")
    }
    
  });