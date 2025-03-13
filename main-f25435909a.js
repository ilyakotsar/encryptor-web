let URLParams = new URLSearchParams(window.location.search);
let tab = URLParams.get('tab');
if (tab) {
    document.getElementById(`${tab}-tab`).classList.remove('hidden');
    document.getElementById(`${tab}-btn`).disabled = true;
} else {
    URLParams.set('tab', 'create');
    window.location.search = URLParams;
}
document.getElementById('source').innerText = window.location.href.split('?')[0];
let encryptionKey;

/**
 * 
 * @param {string} password 
 * @param {string} saltBase64 
 * @param {number|string} iterations 
 * @returns {object}
 */
function getEncryptionKey(password, saltBase64, iterations) {
    let saltWords = CryptoJS.enc.Base64.parse(saltBase64);
    let key = CryptoJS.PBKDF2(password, saltWords, {
        keySize: 256 / 32,
        iterations: Number(iterations),
    });
    return key;
}

/**
 * 
 * @returns {string}
 */
function generateSalt() {
    let saltWords = CryptoJS.lib.WordArray.random(32);
    let saltBase64 = CryptoJS.enc.Base64.stringify(saltWords);
    return saltBase64;
}

/**
 * 
 * @param {string} plaintext 
 * @param {object} key 
 * @returns {[string, string]}
 */
function encryptText(plaintext, key) {
    let ivWords = CryptoJS.lib.WordArray.random(16);
    let encrypted = CryptoJS.AES.encrypt(plaintext, key, {iv: ivWords});
    let ciphertext = CryptoJS.enc.Base64.stringify(encrypted.ciphertext);
    let ivBase64 = CryptoJS.enc.Base64.stringify(ivWords);
    return [ciphertext, ivBase64];
}

/**
 * 
 * @param {string} ciphertext 
 * @param {object} key 
 * @param {string} ivBase64 
 * @returns {string}
 */
function decryptText(ciphertext, key, ivBase64) {
    let ivWords = CryptoJS.enc.Base64.parse(ivBase64);
    let decrypted = CryptoJS.AES.decrypt(ciphertext, key, {iv: ivWords});
    let plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    return plaintext;
}

/**
 * 
 * @param {string} password 
 * @param {string} parameterP 
 * @returns {string}
 */
function getPrivateKey(password, parameterP) {
    let numbers = '';
    [224, 256, 384, 512].forEach(length => {
        let hash = CryptoJS.SHA3(password, {outputLength: length}).toString();
        numbers += bigInt(hash, 16).toString();
    });
    let hash256 = CryptoJS.SHA256(password).toString();
    numbers += bigInt(hash256, 16).toString();
    let hash512 = CryptoJS.SHA512(password).toString();
    numbers += bigInt(hash512, 16).toString();
    let privateKey = numbers.slice(0, parameterP.length - 1);
    return privateKey;
}

/**
 * 
 * @param {string} privateKey 
 * @param {string} parameterG 
 * @param {string} parameterP 
 * @returns {string}
 */
function getPublicKey(privateKey, parameterG, parameterP) {
    let publicKey = bigInt(parameterG).modPow(privateKey, parameterP);
    return String(publicKey);
}

/**
 * 
 * @param {string} privateKey 
 * @param {string} interlocutorPublicKey 
 * @param {string} parameterP 
 * @returns 
 */
function getSharedKey(privateKey, interlocutorPublicKey, parameterP) {
    let sharedKey = bigInt(interlocutorPublicKey).modPow(privateKey, parameterP);
    return String(sharedKey);
}

document.getElementById('create-config-a').addEventListener('click', function() {
    let parameters = document.getElementById('parameters').value;
    let password = document.getElementById('password-create').value;
    if (!parameters || !password) {
        return;
    }
    let parametersArray = parameters.split('_');
    let parameterG = parametersArray[0];
    let parameterP = parametersArray[1];
    let iterations = document.getElementById('iterations-create').value;
    let privateKey = getPrivateKey(password, parameterP);
    let publicKey = getPublicKey(privateKey, parameterG, parameterP);
    let salt = generateSalt();
    let config = ['A', iterations, salt, parameterG, parameterP, publicKey].join('_');
    navigator.clipboard.writeText(config).then(() => {
        document.getElementById('copied-a').innerText = `Copied: ${config}`;
        document.getElementById('copied-a').classList.remove('hidden');
    });
});

document.getElementById('create-config-b').addEventListener('click', function() {
    let configArray = document.getElementById('config-a').value.split('_');
    let password = document.getElementById('password-confirm').value;
    if (!configArray || !password) {
        return;
    }
    let parameterG = configArray[3];
    let parameterP = configArray[4];
    let privateKey = getPrivateKey(password, parameterP);
    let publicKey = getPublicKey(privateKey, parameterG, parameterP);
    configArray[0] = 'B';
    configArray[5] = publicKey;
    let config = configArray.join('_');
    navigator.clipboard.writeText(config).then(() => {
        document.getElementById('copied-b').innerText = `Copied: ${config}`;
        document.getElementById('copied-b').classList.remove('hidden');
    });
});

document.getElementById('get-encryption-key').addEventListener('click', function() {
    let configArray = document.getElementById('config').value.split('_');
    let password = document.getElementById('password-chat').value;
    if (!configArray || !password) {
        return;
    }
    let loader = this.querySelector('.loader');
    loader.classList.remove('hidden');
    let iterations = configArray[1];
    let parameterP = configArray[4];
    let interlocutorPublicKey = configArray[5];
    let privateKey = getPrivateKey(password, parameterP);
    let sharedKey = getSharedKey(privateKey, interlocutorPublicKey, parameterP);
    let salt = generateSalt();
    setTimeout(() => {
        encryptionKey = getEncryptionKey(sharedKey, salt, iterations);
        document.getElementById('chat-body').classList.remove('hidden');
        loader.classList.add('hidden');
    }, 1);
});

document.getElementById('encrypt-message').addEventListener('click', function() {
    let message = document.getElementById('message-chat').value;
    if (!message) {
        return;
    }
    let configArray = document.getElementById('config').value.split('_');
    let user = configArray[0];
    if (user === 'A') {
        user = 'B';
    } else if (user === 'B') {
        user = 'A';
    }
    let [ciphertext, iv] = encryptText(message, encryptionKey);
    let encryptedMessage = [user, iv, ciphertext].join('_');
    navigator.clipboard.writeText(encryptedMessage).then(() => {
        let btn = document.getElementById('encrypt-message');
        let btnText = btn.innerText;
        btn.innerText = 'Copied';
        setTimeout(() => {
            btn.innerText = btnText;
        }, 1000);
    });
});

document.getElementById('decrypt-message').addEventListener('click', function() {
    let encryptedMessage = document.getElementById('encrypted-message-chat').value;
    if (!encryptedMessage) {
        return;
    }
    let encryptedArray = encryptedMessage.split('_');
    let user = encryptedArray[0];
    let iv = encryptedArray[1];
    let ciphertext = encryptedArray[2];
    let plaintext = decryptText(ciphertext, encryptionKey, iv);
    let messageElement = document.createElement('p');
    messageElement.innerText = `${user}: ${plaintext}`;
    messageElement.className = 'mb-4';
    document.getElementById('messages').appendChild(messageElement);
});

document.getElementById('encrypt-symmetric').addEventListener('click', function() {
    let message = document.getElementById('message-symmetric').value;
    let password = document.getElementById('password-symmetric').value;
    if (!message || !password) {
        return;
    }
    let loader = this.querySelector('.loader');
    loader.classList.remove('hidden');
    let iterations = document.getElementById('iterations-symmetric').value;
    let salt = generateSalt();
    setTimeout(() => {
        let encryptionKey = getEncryptionKey(password, salt, iterations);
        let [ciphertext, iv] = encryptText(message, encryptionKey);
        let encryptedMessage = [iterations, salt, iv, ciphertext].join('_');
        document.getElementById('encrypted-message-symmetric').value = encryptedMessage;
        loader.classList.add('hidden');
    }, 1);
});

document.getElementById('decrypt-symmetric').addEventListener('click', function() {
    let encrypted = document.getElementById('encrypted-message-symmetric').value;
    let password = document.getElementById('password-symmetric').value;
    if (!encrypted || !password) {
        return;
    }
    let loader = this.querySelector('.loader');
    loader.classList.remove('hidden');
    let encryptedArray = encrypted.split('_');
    let iterations = encryptedArray[0];
    let salt = encryptedArray[1];
    let iv = encryptedArray[2];
    let ciphertext = encryptedArray[3];
    setTimeout(() => {
        let encryptionKey = getEncryptionKey(password, salt, iterations);
        let plaintext = decryptText(ciphertext, encryptionKey, iv);
        document.getElementById('message-symmetric').value = plaintext;
        document.getElementById('iterations-symmetric').value = iterations;
        let label = document.querySelector('label[for="iterations-symmetric"]');
        label.querySelector('span').innerText = iterations;
        loader.classList.add('hidden');
    }, 1);
});

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        let tab = btn.id.split('-')[0];
        let URLParams = new URLSearchParams(window.location.search);
        URLParams.set('tab', tab);
        window.location.search = URLParams;
    });
});

document.querySelectorAll('[toggle-password]').forEach(btn => {
    btn.addEventListener('click', function() {
        let password = document.getElementById(btn.getAttribute('toggle-password'));
        let icon = btn.querySelector('i');
        if (password.type === 'password') {
            password.type = 'text';
            icon.classList.replace('bi-eye-slash', 'bi-eye');
        } else {
            password.type = 'password';
            icon.classList.replace('bi-eye', 'bi-eye-slash');
        }
    });
});

document.querySelectorAll('input[type="range"]').forEach(input => {
    input.addEventListener('input', function() {
        let label = document.querySelector(`label[for="${input.id}"]`);
        label.querySelector('span').innerText = input.value;
    });
});

document.querySelectorAll('[clear-input]').forEach(btn => {
    btn.addEventListener('click', function() {
        document.getElementById(btn.getAttribute('clear-input')).value = '';
    });
});

document.getElementById('select-parameters').addEventListener('click', function() {
    let url = 'https://raw.githubusercontent.com/ilyakotsar';
    url += '/dh-parameters/refs/heads/main/parameters_2048.json';
    fetch(url)
        .then(response => response.json())
        .then(data => {
            let randomIndex = Math.floor(Math.random() * data['parameters'].length);
            document.getElementById('parameters').value = data['parameters'][randomIndex];
        });
});