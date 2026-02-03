# Password generator with Radio FM module

The project is an IoT system that generates secure passwords using the noise of radio
signals. The system will change frequency every second to connect to a different
radio station. This, in addition to the randomness of the signal, is a good defense
against attacks.
The password will then be encrypted and saved in a database in Google Firebase. Furthermore, the
IoT device records an immutable, digitally signed log event on the blockchain,
to ensure an audit trail, without ever exposing the password itself in plain text.
