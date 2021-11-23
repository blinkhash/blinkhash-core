// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLINKHASH_QT_BLINKHASHADDRESSVALIDATOR_H
#define BLINKHASH_QT_BLINKHASHADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class BlinkhashAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BlinkhashAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** Blinkhash address widget validator, checks for a valid blinkhash address.
 */
class BlinkhashAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit BlinkhashAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // BLINKHASH_QT_BLINKHASHADDRESSVALIDATOR_H
