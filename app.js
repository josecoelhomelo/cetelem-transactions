import axios from 'axios';
import { wrapper } from 'axios-cookiejar-support';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import readline from 'readline';
import { CookieJar } from 'tough-cookie';
const hbEndpoint = 'https://hb.cetelem.pt';
const authEndpoint = `${hbEndpoint}/api/auth`;
const defaultStateDir = '.';
const tokenFileName = '.token';
const cookieFileName = '.cookies.json';
const movementsBatchSize = Number(process.env.MOVEMENTS_BATCH_SIZE) || 5;

const getState = (dir = defaultStateDir) => ({
    dir,
    tokenFile: path.join(dir, tokenFileName),
    cookieFile: path.join(dir, cookieFileName)
});

let token = null;
let state = getState();
let jar = null;
let client = null;

const loadCookieJar = () => {
    if (!fs.existsSync(state.cookieFile)) { return new CookieJar(); }
    try {
        return CookieJar.deserializeSync(JSON.parse(fs.readFileSync(state.cookieFile, 'utf8')));
    } catch {
        return new CookieJar();
    }
};
const ensureStateDir = () => {
    if (!fs.existsSync(state.dir)) { fs.mkdirSync(state.dir, { recursive: true }); }
};
const saveCookieJar = () => {
    ensureStateDir();
    fs.writeFileSync(state.cookieFile, JSON.stringify(jar.serializeSync(), null, 2));
};
const createClient = () => {
    jar = loadCookieJar();
    client = wrapper(axios.create({ jar, withCredentials: true }));
    client.interceptors.response.use((res) => {
        saveCookieJar();
        return res;
    }, (err) => {
        if (err.response) { saveCookieJar(); }
        return Promise.reject(err);
    });
};
const configureState = (dir = defaultStateDir) => {
    state = getState(dir);
    createClient();
};
configureState();
const loadToken = () => {
    if (!fs.existsSync(state.tokenFile)) { return null; }
    return fs.readFileSync(state.tokenFile, 'utf8').trim() || null;
};
const saveToken = (token) => {
    ensureStateDir();
    fs.writeFileSync(state.tokenFile, token, 'utf-8');
};

/**
 * Prompts the user to enter the one-time code sent by SMS.
 * @returns {Promise<string>} Resolves with the entered OTP.
 * @throws {Error} If no code is entered.
 */
const requestOTP = () => new Promise((resolve, reject) => {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    rl.question('Enter the code received through SMS: ', (code) => {
        rl.close();
        if (!code) { reject(Error('Code is required')); }
        resolve(code);
    });
});

/**
 * Validates and normalizes a four-digit OTP.
 * @param {string|number} otp - Four-digit one-time password.
 * @returns {string} OTP without whitespace.
 * @throws {Error} If the OTP is not four digits.
 */
const normalizeOTP = (otp) => {
    const value = String(otp || '').replace(/\s/g, '');
    if (!/^\d{4}$/.test(value)) { throw Error('OTP must contain 4 digits'); }
    return value;
};

/**
 * Hashes a Cetelem password using the same SHA-256 hex digest
 * @param {string} password - Plain-text Cetelem password.
 * @returns {string} SHA-256 hex digest.
 */
const hashPassword = (password) => crypto
    .createHash('sha256')
    .update(password, 'utf8')
    .digest('hex');

/**
 * Starts a Cetelem login session for the given fiscal number.
 * @param {string} fiscalNumber - User fiscal number.
 * @returns {Promise<string>} Resolves with the session hash.
 * @throws {Error} If a captcha is required or the hash is missing.
 */
const createSession = async (fiscalNumber) => {
    const res = await client.post(`${authEndpoint}/sessions`, { fiscalNumber });
    if (res.data?.captchaRequired) { throw Error('Captcha required, log in through the browser first'); }
    if (!res.data?.hash) { throw Error('Session hash not found'); }
    return res.data.hash;
};

/**
 * Submits the hashed password for the current login session.
 * @param {string} hash - Session hash returned by createSession().
 * @param {string} password - Plain-text Cetelem password.
 * @returns {Promise<string>} Resolves with the session hash.
 * @throws {Error} If the hash is missing.
 */
const submitPassword = async (hash, password) => {
    const res = await client.put(`${authEndpoint}/sessions`, { hash, password: hashPassword(password) });
    if (!res.data?.hash) { throw Error('Session hash not found'); }
    return res.data.hash;
};

/**
 * Requests an SMS OTP for the current login session.
 * @param {string} hash - Session hash.
 * @returns {Promise<void>} Resolves when the SMS has been requested.
 */
const sendOTP = async (hash) => {
    await client.post(`${authEndpoint}/users/otp:send`, { hash });
};

/**
 * Validates the SMS OTP and retrieves the Cetelem homebanking auth token.
 * @param {string} hash - Session hash.
 * @param {string|number} otp - Four-digit SMS one-time password.
 * @returns {Promise<string>} Resolves with the auth token.
 * @throws {Error} If the token is missing.
 */
const validateOTP = async (hash, otp) => {
    const res = await client.post(`${authEndpoint}/users/otp:validate`, { otp: normalizeOTP(otp), hash });
    if (!res.data?.jwt) { throw Error('Auth token not found'); }
    return res.data.jwt;
};

/**
 * Creates the authorization headers required by Cetelem API requests.
 * @returns {Object} Request headers containing the current bearer token.
 * @throws {Error} If no token is available.
 */
const authorizedHeaders = () => {
    if (!token) { throw Error('Token missing'); }
    return {
        Authorization: `Bearer ${token}`,
        Source: 'homebanking'
    };
};

/**
 * Retrieves the user's Cetelem cards.
 * @returns {Promise<Array|Object>} Resolves with the raw cards response.
 * @throws {Error} If the request fails or no token is available.
 */
const getCards = () => client.get(`${hbEndpoint}/api/contract/cards`, {
    headers: authorizedHeaders()
})
    .then((res) => res.data)
    .catch((err) => { throw Error('Failed to retrieve cards', { cause: err }); });

/**
 * Reuses a stored auth token after validating it against the cards endpoint.
 * @returns {Promise<string>} Resolves with a valid stored auth token.
 * @throws {Error} If no token exists or validation fails.
 */
const reuseAuthToken = async () => {
    const authToken = loadToken();
    if (!authToken) { throw Error('No auth token found'); }

    token = authToken;
    try {
        await getCards();
        return token;
    } catch (err) {
        token = null;
        throw Error('Reusing auth token failed', { cause: err });
    }
};

/**
 * Logs in the user with the provided Cetelem credentials.
 *
 * The login flow first validates any stored auth token. If that check fails,
 * it runs the full Cetelem login flow and prompts for the SMS OTP when needed.
 *
 * @param {Object} params - Login parameters.
 * @param {string} params.fiscalNumber - User Portuguese fiscal number.
 * @param {string} params.password - User Cetelem password.
 * @param {string|number} [params.otp] - Optional four-digit SMS OTP.
 * @param {string} [params.stateDir='.'] - Directory where `.token.json` and `.cookies.json` are stored.
 * @returns {Promise<string>} Resolves with the Cetelem auth token.
 * @throws {Error} If credentials are missing or login fails.
 */
const login = async (params) => {
    if (!params?.fiscalNumber || !params?.password) {
        throw Error('Login failed', { cause: 'Credentials are required' });
    }

    configureState(params.stateDir);
    token = await reuseAuthToken().catch(() => null);
    if (token) { return token; }

    try {
        let hash = await createSession(params.fiscalNumber);
        hash = await submitPassword(hash, params.password);

        await sendOTP(hash);
        const otp = params.otp || await requestOTP();
        token = await validateOTP(hash, otp);
        saveToken(token);
        saveCookieJar();
        return token;
    } catch (err) {
        throw Error('Login failed', { cause: err });
    }
};

/**
 * Retrieves one movements page from a Cetelem card.
 * @param {string} card - Card contract identifier returned by getCards().
 * @param {number} page - Movements page number.
 * @returns {Promise<Array|Object>} Resolves with the raw movements response.
 * @throws {Error} If the token is missing or the request fails.
 */
const getTransactionsPage = (card, page) => client.get(`${hbEndpoint}/api/contract/${card}/movements/${page}`, {
        headers: authorizedHeaders()
    })
        .then((res) => res.data)
        .catch((err) => { throw Error('Failed to retrieve transactions', { cause: err }); });

/**
 * Retrieves transactions from a Cetelem card in batches of five pages.
 * @param {string} card - Card contract identifier returned by getCards().
 * @param {number|string} [batch=1] - Movements batch number. Batch 1 fetches pages 1-5, batch 2 fetches pages 6-10.
 * @returns {Promise<Array<Object>>} Resolves with the merged movements from the requested batch.
 * @throws {Error} If the card is missing, batch is invalid, token is missing, or the request fails.
 */
const getTransactions = async (card, batch = 1) => {
    if (!card) { throw Error('Failed to retrieve transactions', { cause: 'Card is required' }); }
    if (!Number.isInteger(movementsBatchSize) || movementsBatchSize < 1) {
        throw Error('Failed to retrieve transactions', { cause: 'MOVEMENTS_BATCH_SIZE must be a positive integer' });
    }

    const batchNumber = Number(batch);
    if (!Number.isInteger(batchNumber) || batchNumber < 1) {
        throw Error('Failed to retrieve transactions', { cause: 'Batch must be a positive integer' });
    }

    const startPage = ((batchNumber - 1) * movementsBatchSize) + 1;
    const metadata = await getTransactionsPage(card, 1);
    const totalPages = Number(metadata.pages) || 1;

    if (startPage > totalPages) {
        return [];
    }

    const endPage = Math.min(startPage + movementsBatchSize - 1, totalPages);
    const pages = [];
    for (let page = startPage; page <= endPage; page++) {
        pages.push(page);
    }

    const responses = startPage === 1
        ? [metadata, ...await Promise.all(pages.slice(1).map((page) => getTransactionsPage(card, page)))]
        : await Promise.all(pages.map((page) => getTransactionsPage(card, page)));

    return responses.flatMap((response) => response.movements || []);
};

/**
 * Converts transactions into a CSV string.
 * @param {Array<Object>} transactions - Transactions to export.
 * @param {Array<string>} [headers] - Optional transaction keys to include.
 * @returns {string} CSV content, including the header row.
 * @throws {Error} If transactions are missing or empty.
 */
const toCSV = (transactions, headers) => {
    if (!transactions?.length) { throw Error('Transactions not found'); }
    const useHeaders = Object.keys(transactions[0]).filter((header) => headers?.length ? headers.includes(header) : true);
    const escapeCSV = (value) => {
        const stringValue = String(value);
        return /[",\n\r]/.test(stringValue) ? `"${stringValue.replace(/"/g, '""')}"` : stringValue;
    };
    const body = transactions.reduce((acc, transaction) => {
        const values = useHeaders.map((header) => {
            let value = transaction[header];
            if (value === undefined || value === null) { return ''; }
            return typeof value === 'object' ? JSON.stringify(value) : escapeCSV(value);
        });
        return `${acc}${values.join(',')}\n`;
    }, `${useHeaders.join(',')}\n`);
    return body;
};

/**
 * Saves transactions to a timestamped CSV or JSON file.
 * @param {Array<Object>} transactions - Transactions to save.
 * @param {Object} [csv] - Export options.
 * @param {boolean} [csv.toCSV=true] - Whether to save CSV instead of JSON.
 * @param {Array<string>} [csv.headers=[]] - Optional transaction keys to include in CSV output.
 * @param {string} [folder='transactions'] - Folder where the file will be created.
 * @returns {string} Path of the created file.
 * @throws {Error} If transactions are missing.
 */
const saveTransactions = (transactions, csv = {}, folder = 'transactions') => {
    if (!transactions) { throw Error('Transactions not found'); }
    csv = {
        toCSV: true,
        headers: [],
        ...csv
    };
    if (!fs.existsSync(folder)) { fs.mkdirSync(folder); }
    const date = new Date();
    const timestamp = `${date.getFullYear()}-${(`0` + parseInt(date.getMonth() + 1)).slice(-2)}-${(`0` + date.getDate()).slice(-2)}T${(`0` + date.getHours()).slice(-2)}-${(`0` + date.getMinutes()).slice(-2)}`;
    const extension = csv.toCSV ? 'csv' : 'json';
    const path = `${folder}/${timestamp}.${extension}`;
    const body = csv.toCSV ? toCSV(transactions, csv.headers) : JSON.stringify(transactions);
    fs.writeFileSync(path, body);
    return path;
};

export default { login, getCards, getTransactions, saveTransactions };
