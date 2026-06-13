Node.js module to retrieve transactions from a Cetelem card and save them as CSV or JSON files.

## Installation

Install the package using npm:

```shell
npm install cetelem-transactions
```

Import it into your project:

```js
import cetelem from 'cetelem-transactions';
```

## Example

Saving transactions from the first card to a CSV file:

```js
import cetelem from 'cetelem-transactions';

try {
    await cetelem.login({
        fiscalNumber: '123456789',
        password: 'YourPassword123456'
    });

    const cards = await cetelem.getCards();
    const card = cards[0].contractNumber;
    const transactions = await cetelem.getTransactions(card);
    const path = cetelem.saveTransactions(transactions);

    console.log(`Transactions saved to ${path}`);
} catch (err) {
    console.error(err);
}
```

Saving selected fields:

```js
cetelem.saveTransactions(transactions, {
    headers: ['transactionDate', 'label', 'transactionAmount']
});
```

## Methods

### `login`

Logs in with the provided Cetelem credentials and stores the homebanking auth token in `.token` and session cookies in `.cookies.json` in the state directory.

```js
cetelem.login({
    fiscalNumber: '123456789',
    password: 'YourPassword123456'
});
```

| Property | Definition |
| -------- | ---------- |
| `fiscalNumber` | The user's Portuguese fiscal number. |
| `password` | The user's Cetelem password. |
| `otp` | Optional SMS one-time code. If omitted, the module prompts for it interactively. |
| `stateDir` | Optional directory for `.token` and `.cookies.json`. Defaults to the current working directory. |

The login flow first validates any stored auth token by calling the Cetelem cards endpoint. If that check fails, it falls back to the full login flow and requests the SMS OTP code.

Returns the auth token.

### `getCards`

Retrieves the user's Cetelem cards.

```js
cetelem.getCards();
```

Returns the raw cards response from the Cetelem homebanking API.

### `getTransactions`

Retrieves transactions from a Cetelem card in batches of five movement pages.

```js
cetelem.getTransactions(card, batch);
```

| Argument | Definition |
| -------- | ---------- |
| `card` | Card contract identifier returned by `getCards`. |
| `batch` | Optional batch number. Defaults to `1`; batch `1` fetches pages 1-5, batch `2` fetches pages 6-10, and so on. |

Returns a merged transactions array. If the requested batch has fewer remaining pages than the configured batch size, only existing pages are fetched. If the batch starts after the last available page, an empty array is returned.

Set `MOVEMENTS_BATCH_SIZE` to change how many pages are fetched per batch.

### `saveTransactions`

Saves transactions to a timestamped file. CSV output is enabled by default and files are written to the `transactions` folder unless another folder is passed.

```js
cetelem.saveTransactions(transactions);
```

Write JSON instead:

```js
cetelem.saveTransactions(transactions, { toCSV: false });
```

Write CSV to a custom folder:

```js
cetelem.saveTransactions(transactions, {}, 'exports');
```

CSV options:

| Property | Definition |
| -------- | ---------- |
| `toCSV` | Optional boolean. Defaults to `true`; set to `false` to save JSON. |
| `headers` | Optional array of transaction keys to include in CSV output. Defaults to all keys from the first transaction. |

Returns the created file path, for example `transactions/2026-06-03T00-20.csv`.
