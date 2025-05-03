const editor = document.getElementById('editor');
const saveButton = document.getElementById('saveButton');
const message = document.getElementById('message');
const titleInput = document.getElementById('title-input');
const titleList = document.getElementById('title-list');
const loadingIndicator = document.getElementById('loading');
const newButton = document.getElementById('newButton');
const autoSaveFlag = document.getElementById('autoSaveFlag');
const STORAGE_KEY = 'Text';
const TITLE_LIST_KEY = 'TextTitles';
const LAST_TITLE_KEY = 'lastTitle';
const PRIVATE_KEY = document.getElementById('privateKey');

let titles = [];

function showMessage(msg) {
    message.style.zIndex = '1';
    message.textContent = msg;
    message.classList.remove('error-message');
        message.style.opacity = 0;
    message.style.transition = 'opacity 0.5s ease-in-out';
    message.style.opacity = 1;
        setTimeout(() => {
        message.style.opacity = 0;
        setTimeout(() => {
            message.textContent = '';
            message.style.transition = '';
            message.style.zIndex = '-1';
        }, 500); // Wait for fade out
    }, 3000);
}

function showGenerateKeyMessage(key) {
    const overlay = document.getElementById('generateKeyOverlay');
    const messageBox = document.getElementById('generateKeyMessage');
    const keyDisplay = messageBox.querySelector('.key-display');
    const copyButton = messageBox.querySelector('.copy-button');
    const copyText = copyButton.querySelector('.copy-text');
    const confirmButton = messageBox.querySelector('.submit-button');

    keyDisplay.textContent = key;
    copyButton.onclick = () => {
        navigator.clipboard.writeText(key)
            .then(() => {
                copyText.textContent = 'コピーしました！';
                copyText.style.color = '#4CAF50';
                setTimeout(() => {
                    copyText.textContent = 'キーをコピー';
                    copyText.style.color = '';
                }, 2000);
                PRIVATE_KEY.value = key;
            })
            .catch(err => {
                console.error('キーのコピーに失敗しました:', err);
                copyText.textContent = 'コピー失敗';
                copyText.style.color = '#dc3545';
                setTimeout(() => {
                    copyText.textContent = 'キーをコピー';
                    copyText.style.color = '';
                }, 2000);
            });
    };
    confirmButton.onclick = () => {
        overlay.classList.add('hidden');
    };
    overlay.classList.remove('hidden');
}

function showRequireKeyMessage() {
    const messageContainer = document.createElement('div');
    messageContainer.classList.add('key-message');
    const messageText = document.createElement('p');
    messageText.textContent = '暗号化されたテキストを読み込むには、PRIVATE_KEY欄にキーを入力してください。';
    messageContainer.appendChild(messageText);
    message.innerHTML = '';
    message.appendChild(messageContainer);
    message.style.zIndex = '1';
    message.style.opacity = 1;
    setTimeout(() => {
        message.style.opacity = 0;
        setTimeout(() => {
            message.innerHTML = '';
            message.style.zIndex = '-1';
        }, 500);
    }, 5000);
}

//////////////////// 暗号化機能 ////////////////////////////

function generateRandomBytes(byteLength) {
    if (typeof window === 'undefined' || !window.crypto || !window.crypto.getRandomValues) {
      throw new Error("Web Crypto API が利用できません。");
    }
  
    const byteArray = new Uint8Array(byteLength);
    window.crypto.getRandomValues(byteArray);
    return byteArray;
}

function bytesToHexString(bytes) {
    return Array.from(bytes)
      .map(byte => byte.toString(16).padStart(2, '0'))
      .join('');
}
  
function hexStringToBytes(hexString) {
    if (hexString.length % 2 !== 0) {
      throw new Error("16進数文字列は偶数長の必要があります。");
    }
    const byteLength = hexString.length / 2;
    const byteArray = new Uint8Array(byteLength);
    for (let i = 0; i < byteLength; i++) {
      const hexPair = hexString.substring(i * 2, (i + 1) * 2);
      byteArray[i] = parseInt(hexPair, 16);
    }
    return byteArray;
}

// エンコード（暗号化）関数
async function encode(text, ivHex, keyHex) {
    try {
        // 16進数文字列からバイト配列に変換
        const iv = hexStringToBytes(ivHex);
        const keyData = hexStringToBytes(keyHex);

        // キーをインポート
        const key = await window.crypto.subtle.importKey(
            'raw',
            keyData,
            'AES-GCM',
            true,
            ['encrypt']
        );

        // テキストをUint8Arrayに変換
        const textEncoder = new TextEncoder();
        const encodedText = textEncoder.encode(text);

        // 暗号化を実行
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encodedText
        );

        // 暗号化されたデータを16進数文字列に変換して返す
        return bytesToHexString(new Uint8Array(encryptedData));
    } catch (error) {
        console.error('暗号化エラー:', error);
        throw error;
    }
}

// ランダムなIVとキーを生成して暗号化を実行する関数
async function encodeWithRandomKey(text) {
    try {
        // ランダムな初期化ベクトル（IV）を生成
        const iv = generateRandomBytes(12);
        const ivHex = bytesToHexString(iv);

        // ランダムな暗号化キーを生成
        const key = await window.crypto.subtle.generateKey(
            {
                name: 'AES-GCM',
                length: 256
            },
            true,
            ['encrypt', 'decrypt']
        );

        // キーをエクスポートして16進数文字列に変換
        const exportedKey = await window.crypto.subtle.exportKey('raw', key);
        const keyHex = bytesToHexString(new Uint8Array(exportedKey));

        // 暗号化を実行
        const encryptedData = await encode(text, ivHex, keyHex);

        // 暗号化されたデータ、IV、キーを結合して返す
        return {
            data: encryptedData,
            iv: ivHex,
            key: keyHex
        };
    } catch (error) {
        console.error('暗号化エラー:', error);
        throw error;
    }
}

// デコード（復号化）関数
async function decode(encryptedObj) {
    try {
        // 16進数文字列をUint8Arrayに変換
        const encryptedData = hexStringToBytes(encryptedObj.data);
        const iv = hexStringToBytes(encryptedObj.iv);
        const keyData = hexStringToBytes(encryptedObj.key);

        // キーをインポート
        const key = await window.crypto.subtle.importKey(
            'raw',
            keyData,
            'AES-GCM',
            true,
            ['decrypt']
        );

        // 復号化を実行
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encryptedData
        );

        // Uint8Arrayを文字列に変換
        const textDecoder = new TextDecoder();
        return textDecoder.decode(decryptedData);
    } catch (error) {
        console.error('復号化エラー:', error);
        throw error;
    }
}

// 16進数文字列をバイト配列に変換
function hexStringToBytes(hexString) {
    const bytes = new Uint8Array(hexString.length / 2);
    for (let i = 0; i < hexString.length; i += 2) {
        bytes[i / 2] = parseInt(hexString.substr(i, 2), 16);
    }
    return bytes;
}

//////////////////// 保存機能 ////////////////////////////
function createTitleData(title, text, iv) {
    return {
        title: title,
        text : text,
        lastUpdated: new Date().toLocaleString(),
        iv : iv
    };
}

function saveToStorage(title, text, titleData) {
    const existingIndex = getIndex(title); 

    if (existingIndex > -1) {
        titles[existingIndex] = titleData;
    } else {
        titles.push(titleData);
    }
    localStorage.setItem(TITLE_LIST_KEY, JSON.stringify(titles));
    updateTitleList();
}

async function save(title, textToSave) {
    const keyHex = PRIVATE_KEY.value.trim();
    if (!keyHex) {
        // キー未入力時はランダムキーで暗号化し、ユーザーに通知
        try {
            const result = await encodeWithRandomKey(textToSave);
            const titleData = createTitleData(title, result.data, result.iv);
            saveToStorage(title, result.data, titleData);
            localStorage.setItem(LAST_TITLE_KEY, title);
            showGenerateKeyMessage(result.key);
        } catch (error) {
            showMessage('暗号化に失敗しました。');
        }
        return;
    }
    // キー入力時は通常通り暗号化
    const iv = generateRandomBytes(12);
    const ivHex = bytesToHexString(iv);
    try {
        const encryptedData = await encode(textToSave, ivHex, keyHex);
        const titleData = createTitleData(title, encryptedData, ivHex);
        saveToStorage(title, encryptedData, titleData);
        localStorage.setItem(LAST_TITLE_KEY, title);
    } catch (error) {
        showMessage('暗号化に失敗しました。');
    }
}

function getIndex(title) {
       return titles.findIndex((t) => t.title === title);
}

function saveText() {
    const textToSave = editor.value;
    const title = titleInput.value.trim();
    if (title === "") {
        showMessage("タイトルを入力してください。");
        return;
    }

    try {
        save(title, textToSave);
        setTimeout(() => {
            showMessage('テキストを保存しました。');
        }, 500);
    } catch (error) {
        console.error('テキストの保存に失敗しました:', error);
        message.textContent = 'テキストの保存に失敗しました。';
        message.classList.add('error-message');
        loadingIndicator.style.display = 'none';
    }
}

///////////////////////// オートセーブ /////////////////////////////

function autoSave() {
    if (!autoSaveFlag.checked) return;

    const baseTitle = titleInput.value.trim();
    const autoSaveTitle = `[Auto Save]${baseTitle}`;
    const textToSave = editor.value;

    try {
        save(autoSaveTitle, textToSave);
    } catch (error) {
        console.error('自動保存に失敗しました:', error);
    }
}

///////////////////////// ロード /////////////////////////////

function getTitleData(title) {
    const existingIndex = getIndex(title); 

    if (existingIndex > -1) {
        return titles[existingIndex];
    } else {
        return undefined;
    }

}

function load(title, savedText) {
    editor.value = savedText;
    showMessage(`${title} を読み込みました。`);
    titleInput.value = title.replace('[Auto Save]', '');
}

function newText() {
    editor.value = '';
    titleInput.value = '';
    showMessage('新しいテキストエディタです。');
}

async function tryLoadText(title) {
    const titledata = getTitleData(title);
    if (!titledata) {
        newText();
        return;
    }
    const keyHex = PRIVATE_KEY.value.trim();
    if (!keyHex) {
        showRequireKeyMessage();
        return;
    }
    try {
        const encryptedObj = { data: titledata.text, iv: titledata.iv, key: keyHex };
        const savedText = await decode(encryptedObj);
        load(title, savedText);
    } catch (error) {
        showMessage('復号化に失敗しました。キーが正しいか確認してください。');
    }
}

///////////////////////// タイトルリストの表示部分を作成 /////////////////////////////

function makeDateDisplay (lastUpdated) {
    const dateDisplay = document.createElement('span');
    dateDisplay.textContent = lastUpdated;
    dateDisplay.classList.add('date-display');
    return dateDisplay;
}

function makeTitleListItem (title) {
    const li = document.createElement('li');
    li.textContent = title;
    li.addEventListener('click', () => tryLoadText(title));
    return li;
}

function makeDeleteButton (title) {
    const deleteButton = document.createElement('button');
    deleteButton.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" height="17px" viewBox="0 -960 960 960" width="24px" fill="#FfFfFf"><path d="M280-120q-33 0-56.5-23.5T200-200v-520h-40v-80h200v-40h240v40h200v80h-40v520q0 33-23.5 56.5T680-120H280Zm400-600H280v520h400v-520ZM360-280h80v-360h-80v360Zm160 0h80v-360h-80v360ZM280-720v520-520Z"/></svg>';
    deleteButton.classList.add('delete-button');
    deleteButton.addEventListener('click', (event) => {
        event.stopPropagation(); // Prevent loading the text
        deleteText(title);
    });
    return deleteButton;
}

function updateTitleList() {
    titleList.innerHTML = '';
    titles.sort(
        (a, b) => new Date(b.lastUpdated) - new Date(a.lastUpdated)
    );
    titles.forEach((item) => {
        const li = makeTitleListItem(item.title);
        const dateDisplay = makeDateDisplay(item.lastUpdated);
        const deleteButton = makeDeleteButton(item.title)
        li.appendChild(dateDisplay);
        li.appendChild(deleteButton);
        titleList.appendChild(li);
    });
}

///////////////////////// タイトルリストを読み込み /////////////////////////////

function loadTitleList() {
    const savedTitles = localStorage.getItem(TITLE_LIST_KEY);
    var loadedtitles = []
    if (savedTitles) {
        try {
            loadedtitles = JSON.parse(savedTitles);
        } catch (error) {
            console.error('タイトルの読み込みに失敗しました:', error);
            message.textContent = 'タイトルの読み込みに失敗しました。';
            message.classList.add('error-message');
        }
    }
    return loadedtitles
}

function loadTitles() {
    titles = loadTitleList()
    updateTitleList();
}

///////////////////////// 削除機能 /////////////////////////////

function deleteText(title) {
    if (confirm(`「${title}」を削除しますか？`)) {
        try {
            localStorage.removeItem(title);

            titles = titles.filter((t) => t.title !== title);
            localStorage.setItem(TITLE_LIST_KEY, JSON.stringify(titles));
            updateTitleList();

            showMessage(`「${title}」を削除しました。`);
            // Clear the editor if the deleted title was currently loaded
            if (titleInput.value === title) {
                editor.value = '';
                titleInput.value = '';
            }
        } catch (error) {
            console.error('テキストの削除に失敗しました:', error);
            message.textContent = 'テキストの削除に失敗しました。';
            message.classList.add('error-message');
        }
    }
}


//////////////////////// debounce関数 (連発された処理を間引く) /////////////////

function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => {
        func.apply(this, args);
      }, delay);
    };
}

const debouncedAutoSave = debounce(autoSave, 500); // 500ms間隔で保存

///////////////////////// 機能実装 //////////////////////////////////

saveButton.addEventListener('click', saveText);
newButton.addEventListener('click', newText);
editor.addEventListener('input', debouncedAutoSave);
titleInput.addEventListener('input', debouncedAutoSave);
loadTitles()

window.addEventListener('load', () => {
    // Load the last edited title on page load
    const lastTitle = localStorage.getItem(LAST_TITLE_KEY);
    if (lastTitle) {
        tryLoadText(lastTitle);
    } else {
        // 最後に編集したタイトルがない場合は、最新のAutoSaveを探す
        const autoSaveTitle = titles.find(t => t.title.startsWith('[Auto Save]'));
        if (autoSaveTitle) {
            tryLoadText(autoSaveTitle.title);
        }
    }
});
