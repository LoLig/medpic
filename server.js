const express = require('express');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const Swal = require('sweetalert2');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const saltRounds = 10; // Cost factor for hashing
const algorithm = 'aes-256-cbc';
//const secretKey = process.env.SECR_KEY; // Should be 32 bytes for aes-256-cbc
const iv = crypto.randomBytes(16); // Initialization vector
const secretKey = crypto.randomBytes(32).toString('hex');
const jwtSecret = secretKey;

const app = express();
const PORT = process.env.PORT || 2001;
const HOST = process.env.HOST || '0.0.0.0'; // Default to listen on all network interfaces

/*
// Create a MySQL pool
const pool = mysql.createPool({
    host: 'web0098.zxcs.nl',
    port: '2222',
    user: 'u72967p69489_medpic',
    password: '7puy#sd58josPZyY',
    database: 'u72967p69489_medpicdb',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // Add Quotaguard Static proxy settings
    stream: require('quotaguardstatic').tunnel({
        host: quotaguardStaticUrl.hostname,
        port: quotaguardStaticUrl.port,
        proxyAuth: {
            username: quotaguardStaticUrl.username,
            password: quotaguardStaticUrl.password
        }
    })
});
*/

// Parse the Quotaguard Static URL
const quotaguardStaticUrl = new URL(process.env.QUOTAGUARDSTATIC_URL);

// Create a MySQL pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    // Add Quotaguard Static proxy settings
    stream: require('quotaguardstatic').tunnel({
        host: quotaguardStaticUrl.hostname,
        port: quotaguardStaticUrl.port,
        proxyAuth: {
            username: quotaguardStaticUrl.username,
            password: quotaguardStaticUrl.password
        }
    })
});


async function testDatabaseConnection() {
    try {
        const [rows] = await pool.query('SELECT 1 + 1 AS solution');
        console.log('Database connection test successful: ', rows[0].solution);
    } catch (err) {
        console.error('Database connection test failed:', err);
        process.exit(1);
    }
}

testDatabaseConnection();

// Ensure the key is 32 bytes for AES-256
const secretKey2 = Buffer.from(process.env.SECRET_KEY_2 || 'default_secret_key').slice(0, 32);

function encrypt(text) {
    const iv = crypto.randomBytes(16); // Generate a new IV for each encryption
    let cipher = crypto.createCipheriv(algorithm, secretKey2, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(text) {
    try {
        let iv = Buffer.from(text.iv, 'hex');
        let encryptedText = Buffer.from(text.encryptedData, 'hex');
        let decipher = crypto.createDecipheriv(algorithm, secretKey2, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (error) {
        console.error('Decryption failed:', error);
        throw new Error('Decryption failed due to internal error.');
    }
}

// Increase request size limit (for JSON payloads)
app.use(bodyParser.json({ limit: '50mb' }));

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ?';
    try {
        const [results] = await pool.query(sql, [username]);
        if (results.length > 0) {
            const user = results[0];

            try {
                const match = await bcrypt.compare(password, user.password);
                if (match) {
                    const userData = {
                        id: user.id,
                        name: user.name,
                        organization: user.organization,
                        username: user.username,
                        rights: user.rights,
                        hap: user.hap
                    };
                    const token = jwt.sign({ id: user.id, username: user.username }, jwtSecret, { expiresIn: '1000y' });
                    const isFirstLogin = user.first_login === 'yes';

                    res.json({ success: true, token, userData, isFirstLogin });
                } else {
                    res.json({ success: false, message: 'Invalid credentials' });
                }
            } catch (err) {
                console.error('Error comparing password:', err);
                res.status(500).json({ success: false, message: 'Error processing your request' });
            }
        } else {
            res.json({ success: false, message: 'User not found' });
        }
    } catch (error) {
        console.error('Error executing query:', error);
        res.status(500).json({ success: false, message: 'Database query failed' });
    }
});

// Serve static files (HTML, CSS, JS)
app.use(express.static('public'));
//app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/users/request-password-reset', async (req, res) => {
    const { email } = req.body;
    const resetPasswordToken = crypto.randomBytes(20).toString('hex');
    const resetPasswordExpires = new Date(Date.now() + 10800000); // Token expires in 1 hour

    try {
        // SQL to update the user record with the reset token and expiration
        const sql = `
            UPDATE users
            SET reset_password_token = ?, reset_password_expires = ?
            WHERE username = ?
        `;
        const [results] = await pool.query(sql, [resetPasswordToken, resetPasswordExpires, email]);

        if (results.affectedRows === 0) {
            // No user found with the email address
            return res.status(404).send('No account with that email address exists.');
        }

        const transporter = nodemailer.createTransport({
          service: "hotmail",
          auth: {
              user: "efluitman@hotmail.com",
              pass: "009510.Piet!"
          }
        });

        const mailOptions = {
            from: `MedPic <efluitman@hotmail.com>`,
            to: email,
            subject: 'Password Reset',
            html: `
                U ontvangt dit bericht omdat u (of iemand anders) een verzoek heeft ingediend om het wachtwoord voor uw account opnieuw in te stellen.<br><br>
                Klik op de volgende link of kopieer deze naar uw browser om het proces te voltooien:<br><br>
                <a href="http://${req.headers.host}/reset-password.html?token=${resetPasswordToken}">Wachtwoord opnieuw instellen</a><br><br>
                Als u dit niet heeft aangevraagd, negeer dan deze e-mail en uw wachtwoord zal niet worden gewijzigd.
            `
        };

        await transporter.sendMail(mailOptions);
        res.json({ message: 'An email has been sent to ' + email + ' with further instructions.' });
    } catch (error) {
        console.error('Error during password reset process:', error);
        res.status(500).json({ message: 'Error processing your request', details: error.message });
    }
});


// Handle POST request to send email
app.post('/send-email', async (req, res) => {
    try {
        const { patientNumber, imagesData, name, organization, username } = req.body;

        const [orgResults] = await pool.execute('SELECT * FROM organizations WHERE id = ?', [organization]);
        if (orgResults.length === 0) {
            return res.status(404).send({ message: 'Organization not found.' });
        }
        const orgData = orgResults[0];

        const [hapResults] = await pool.execute('SELECT hap, smtp, port, email_sending, password_iv, password_encrypted, email_receiving FROM hap WHERE id = ?', [orgData.hap]);
        if (hapResults.length === 0) {
            return res.status(404).send({ message: 'HAP settings not found for the given organization.' });
        }
        const hapData = hapResults[0];

        console.error('hapData:', orgData.hap, hapData.password_iv, hapData.password_encrypted);

        const pw_decrypted = decrypt({
            iv: hapData.password_iv,
            encryptedData: hapData.password_encrypted
        });

        const attachments = imagesData.map((image, index) => ({
            filename: `image${index + 1}.jpg`,
            content: image.split('base64,')[1],
            encoding: 'base64'
        }));

        const transporter = nodemailer.createTransport({
            host: hapData.smtp,
            port: hapData.port,
            secure: false,
            auth: {
                user: hapData.email_sending,
                pass: pw_decrypted
            },
            tls: {
                rejectUnauthorized: false
            }
        });

        const mailOptions = {
            from: `${hapData.hap} <${hapData.email_sending}>`,
            to: `${hapData.email_receiving}`,
            subject: 'Medische foto',
            replyTo: username,
            html: `
                <p>Verzonden door: ${name} van ${orgData.organization}</p>
                <p>Patiëntnummer: ${patientNumber}</p>
                <p>Reply to: ${username}</p>
            `,
            attachments: attachments
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send({ message: 'Email sent successfully' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).send({ message: 'Failed to send email', details: error.message });
    }
});

// Fetch haps
app.get('/api/haps', async (req, res) => {
    const sql = 'SELECT * FROM hap';
    try {
        const [results] = await pool.query(sql);
        res.json({ haps: results });
    } catch (error) {
        console.error('Error fetching HAPs:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

// Fetch organizations
app.get('/api/organizations', async (req, res) => {
    let sql = 'SELECT id, organization, `group`, hap FROM organizations';
    const hapId = req.query.hapId;

    if (hapId) {
        sql += ' WHERE hap = ?';
    }
    try {
        const [results] = await pool.query(sql, hapId ? [hapId] : []);
        console.log("Organization result:", results);
        res.json({ organizations: results });
    } catch (error) {
        console.error('Error fetching organizations:', error);
        res.status(500).send('Error fetching organizations');
    }
});

app.get('/api/users', async (req, res) => {
    let sql = `
        SELECT users.*, organizations.organization AS organization_name
        FROM users
        LEFT JOIN organizations ON users.organization = organizations.id
    `;
    const params = [];
    const { hapId } = req.query;
    // Log the final SQL query and parameters to debug
    console.log('hapId:', hapId);
    if (hapId) {
        sql += ' WHERE users.hap = ?'; // Make sure the column name is correct and fully qualified if necessary
        params.push(hapId);
    }

    // Log the final SQL query and parameters to debug
    console.log('Executing SQL:', sql);
    console.log('With parameters:', params);

    try {
        const [results] = await pool.query(sql, params);
        console.log('Query results:', results); // Log results to see what is actually returned
        if (results.length === 0) {
            console.log('No users found for the provided criteria.');
            return res.status(404).json({ message: 'No users found' });
        }
        res.json({ users: results });
    } catch (error) {
        console.error('Error fetching users with organization names:', error);
        res.status(500).json({ error: 'Internal server error', details: error.message });
    }
});

// Update hap endpoint
app.post('/api/hap/update', async (req, res) => {
    const { id, hap, email } = req.body;

    const sql = 'UPDATE hap SET hap = ?, `email` = ? WHERE id = ?';
    try {
        const [results] = await pool.query(sql, [hap, email, id]);
        if (results.affectedRows === 0) {
            // No rows were updated, which typically means the target doesn't exist
            return res.status(404).send({ message: 'HAP not found or no changes made' });
        }
        res.send({ message: 'HAP updated successfully', hap: { id, hap, email } });
    } catch (error) {
        console.error('Error updating HAP:', error);
        res.status(500).send({ message: 'Error updating HAP', details: error.message });
    }
});


// Update organization endpoint
app.post('/api/organizations/update', async (req, res) => {
    const { id, organization, group } = req.body;

    const sql = 'UPDATE organizations SET organization = ?, `group` = ? WHERE id = ?';
    try {
        const [results] = await pool.query(sql, [organization, group, id]);
        if (results.affectedRows === 0) {
            // No rows were updated, which often means the target doesn't exist
            return res.status(404).send({ message: 'Organization not found or no changes made' });
        }
        res.send({ message: 'Organization updated successfully', organization: { id, organization, group } });
    } catch (error) {
        console.error('Error updating organization:', error);
        res.status(500).send({ message: 'Error updating organization', details: error.message });
    }
});

// Update user endpoint
app.post('/api/users/update', async (req, res) => {
    const { id, name, email, rights } = req.body;

    const sql = 'UPDATE users SET name = ?, username = ?, rights = ? WHERE id = ?';
    try {
        const [results] = await pool.query(sql, [name, email, rights, id]);
        if (results.affectedRows === 0) {
            // No rows were updated, which typically means the target doesn't exist
            return res.status(404).send({ message: 'User not found or no changes made' });
        }
        res.send({ message: 'User updated successfully', user: { id, name, email, rights } });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).send({ message: 'Error updating user', details: error.message });
    }
});

// Endpoint to add a hap
app.post('/api/hap/add', async (req, res) => {
    const { name, user, job, email } = req.body;
    const defaultPassword = "medpic"; // Standard password for all new users
    // SQL to insert into the HAP table
    const insertHapSql = 'INSERT INTO hap (hap, email) VALUES (?, ?)';

    try {
        // Insert the new HAP entry and retrieve the inserted ID
        const [hapResults] = await pool.query(insertHapSql, [name, email]);
        const newHapId = hapResults.insertId;

        // SQL to insert a corresponding entry into the organizations table and retrieve the inserted ID
        const insertOrgSql = 'INSERT INTO organizations (organization, `group`, hap) VALUES (?, "Huisartsenpraktijk", ?)';
        const [orgResults] = await pool.query(insertOrgSql, [name, newHapId]);
        const newOrgId = orgResults.insertId;

        // SQL to insert a corresponding entry into the users table
        const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);
        const insertUsrSql = 'INSERT INTO users (name, organization, username, rights, `function`, hap, password) VALUES (?, ?, ?, "admin", ?, ?, ?)';
        await pool.execute(insertUsrSql, [user, newOrgId, email, job, newHapId, hashedPassword]);

        const transporter = nodemailer.createTransport({
          service: "hotmail",
          auth: {
              user: "efluitman@hotmail.com",
              pass: "009510.Piet!"
          }
        });

        const mailOptions = {
            from: `MedPic <efluitman@hotmail.com>`,
            to: email,
            subject: `Toegevoegd als adminstrator van ${name} voor MedPic`,
            html: `
                Beste ${user},<br><br>
                ${name} is toegevoegd aan <b>MedPic</b> met u als administrator.<br><br>
                Met MedPic kun je veilig, direct en snel medische foto's versturen.<br><br>
                Ga naar: <a href="https://medpic.manfluit.nl">MedPic</a><br><br>
                Log de eerste keer in met je emailadres en als paswoord <b>medpic</b><br>
                Het wachtwoord dien je dan meteen aan te passen.<br><br>
                Voor toegang tot het administratie gedeelte dien je ingelogd te zijn op een computer, niet op een mobiele telefoon.<br>
                Als administrator kun je organisaties en gebruikers per organisatie toevoegen die veilig foto's naar de praktijk kunnen versturen.<br><br>
                Succes en met vriendelijke groeten,<br><br>
                Ernst Fluitman<br>
                Huisarts en bedenker van MedPic
            `
        };

        await transporter.sendMail(mailOptions);

        // Send success response back
        res.send({ message: 'Huisartsenpraktijk and corresponding organization added successfully' });
    } catch (error) {
        console.error('Error adding HAP or organization:', error);
        res.status(500).send({ message: 'Error adding HAP or organization', details: error.message });
    }
});

// Endpoint to add a organization
app.post('/api/organization/add', async (req, res) => {
    const { name, group, hap } = req.body;

    const sql = 'INSERT INTO organizations (organization, `group`, hap) VALUES (?, ?, ?)';
    try {
        const [results] = await pool.query(sql, [name, group, hap]);
        // Since it's an insert operation, you can check if the affectedRows is 1 for a successful insertion
        if (results.affectedRows === 1) {
            res.send({ message: 'Organisatie toegevoegd' });
        } else {
            // If no rows were affected, it means the insert didn't take place
            throw new Error('Insert failed, no rows affected.');
        }
    } catch (error) {
        console.error('Error adding Organization:', error);
        res.status(500).send({ message: 'Error adding Organization', details: error.message });
    }
});

// Endpoint to add a user
app.post('/api/users/add', async (req, res) => {
    const { name, organization, email, rights, job, hap } = req.body;
    const defaultPassword = "medpic"; // Standard password for all new users

    try {
        // Fetch organization name
        const [orgResults] = await pool.execute('SELECT organization FROM organizations WHERE id = ?', [organization]);
        const orgName = orgResults.length > 0 ? orgResults[0].organization : 'Unknown Organization';

        // Check HAP settings before adding the user
        const [hapResults] = await pool.execute('SELECT hap, smtp, port, email_sending, password_iv, password_encrypted FROM hap WHERE id = ?', [hap]);
        if (hapResults.length > 0 && hapResults[0].password_iv) {
            console.log(`Step 0`);

            const hapData = hapResults[0];
            const pw_decrypted = decrypt({
                iv: hapData.password_iv,
                encryptedData: hapData.password_encrypted
            });

            // Email transporter setup
            const transporter = nodemailer.createTransport({
                host: hapData.smtp,
                port: hapData.port,
                secure: false,
                auth: {
                    user: hapData.email_sending,
                    pass: pw_decrypted
                },
                tls: {
                    rejectUnauthorized: false
                }
            });

            // Email options
            const mailOptions = {
                from: `${hapData.hap} <${hapData.email_sending}>`,
                to: email,
                subject: 'Toegevoegd als gebruiker van MedPic',
                html: `
                    Beste ${name},<br><br>
                    Je bent toegevoegd aan <b>MedPic</b>.<br><br>
                    Met MedPic kun je veilig, direct en snel medische foto's versturen naar ${hapData.hap} namens ${orgName}. Direct met je eigen mobiele camera zodat we goede kwaliteit foto's krijgen.<br>
                    De foto's worden ook niet op je eigen telefoon bewaard.<br><br>
                    Ga naar: <a href="https://medpic.manfluit.nl">MedPic</a><br>
                    Log de eerste keer in met je emailadres en als paswoord <b>medpic</b><br>
                    Het wachtwoord dien je dan meteen aan te passen.<br><br>
                    Succes en met vriendelijke groeten,<br><br>
                    Ernst Fluitman<br>
                    Huisarts en bedenker van MedPic
                  `
            };

            // Send email
            await transporter.sendMail(mailOptions);
            console.log(`Step 1`);

            // Add user to database
            const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);
            const userSql = 'INSERT INTO users (name, organization, username, rights, `function`, hap, password) VALUES (?, ?, ?, ?, ?, ?, ?)';
            await pool.execute(userSql, [name, organization, email, rights, job, hap, hashedPassword]);
            console.log(`Step 2`);

            res.json({ message: 'User added and email sent successfully.' });
        } else {
            console.log(`Step 4`);
            // If the password_iv is not available, inform the client to set up email settings first
            res.status(400).json({ message: 'Please configure email settings in Instellingen first.' });
        }
    } catch (error) {
        console.log(`Step 6`);
        console.error('Error in user addition or email sending:', error);
        res.status(500).json({ message: 'Error processing your request', details: error.message });
    }
});

/*
app.post('/api/users/add', async (req, res) => {
    const { name, organization, email, rights, job, hap } = req.body;
    const defaultPassword = "medpic"; // Standard password for all new users

    try {
        const hashedPassword = await bcrypt.hash(defaultPassword, saltRounds);
        const userSql = 'INSERT INTO users (name, organization, username, rights, `function`, hap, password) VALUES (?, ?, ?, ?, ?, ?, ?)';
        await pool.execute(userSql, [name, organization, email, rights, job, hap, hashedPassword]);

        const [hapResults] = await pool.execute('SELECT hap, smtp, port, email_sending, password_iv, password_encrypted FROM hap WHERE id = ?', [hap]);
        if (hapResults.length > 0) {
          console.log(`Step 0`);
          if (hapResults[0].password_iv) {
            console.log(`Step 1`);

            const hapData = hapResults[0];
            const pw_decrypted = decrypt({
                iv: hapData.password_iv,
                encryptedData: hapData.password_encrypted
            });

            const transporter = nodemailer.createTransport({
                host: hapData.smtp,
                port: hapData.port,
                secure: false,
                auth: {
                    user: hapData.email_sending,
                    pass: pw_decrypted
                },
                tls: {
                    rejectUnauthorized: false
                }
            });

            const mailOptions = {
                from: `${hapData.hap} <${hapData.email_sending}>`,
                to: email,
                subject: 'Toegevoegd als gebruiker van MedPic',
                html: `
                    Beste ${name},<br><br>
                    Je bent toegevoegd aan <b>MedPic</b>.<br><br>
                    Met MedPic kun je veilig, direct en snel medische foto's versturen naar ${hapData.hap} namens ${orgName}. Direct met je eigen mobiele camera zodat we goede kwaliteit foto's krijgen.<br>
                    De foto's worden ook niet op je eigen telefoon bewaard.<br><br>
                    Ga naar: <a href="https://medpic.manfluit.nl">MedPic</a><br>
                    Log de eerste keer in met je emailadres en als paswoord <b>medpic</b><br>
                    Het wachtwoord dien je dan meteen aan te passen.<br><br>
                    Succes en met vriendelijke groeten,<br><br>
                    Ernst Fluitman<br>
                    Huisarts en bedenker van MedPic
                  `
            };

            await transporter.sendMail(mailOptions);
            console.log(`Step 2`);

            // Fetch organization name
            const [orgResults] = await pool.execute('SELECT organization FROM organizations WHERE id = ?', [organization]);
            const orgName = orgResults.length > 0 ? orgResults[0].organization : 'Unknown Organization';

            console.log(`Step 3`);

            res.json({ message: 'User added and email sent successfully.' });
          }
          else {
            console.log(`Step 4`);
            // If the password_iv is not available, inform the client to set up email settings
            res.status(400).json({ message: 'Please configure email settings in Instellingen first.' });
          }
        } else {
            console.log(`Step 5`);
            throw new Error('No HAP data found.');
        }
    } catch (error) {
        console.log(`Step 6`);
        console.error('Error in user addition or email sending:', error);
        res.status(500).json({ message: 'Error processing your request', details: error.message });
    }
});
*/

app.post('/api/users/update-password', async (req, res) => {
    const { username, newPassword } = req.body;

    try {
        const hash = await bcrypt.hash(newPassword, saltRounds);
        const sql = 'UPDATE users SET password = ?, first_login = "no" WHERE username = ?';
        const [results] = await pool.query(sql, [hash, username]);

        if (results.affectedRows === 0) {
            // No rows were updated, which typically means the user was not found
            return res.status(404).send({ message: 'User not found' });
        }
        res.send({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).send({ message: 'Error updating password', details: error.message });
    }
});

app.get('/api/hap-names', async (req, res) => {
    const sql = 'SELECT id, hap FROM hap';

    try {
        const [results] = await pool.query(sql);
        // Convert each row into an object with 'id' and 'name' properties
        const hapNames = results.map(row => ({
            id: row.id,
            name: row.hap
        }));
        res.json({ hapNames });
    } catch (error) {
        console.error('Error fetching HAP names:', error);
        res.status(500).send({ message: 'Error fetching HAP names', details: error.message });
    }
});

app.get('/api/hap-name/:id', async (req, res) => {
    const { id } = req.params;
    const sql = 'SELECT hap FROM hap WHERE id = ?';

    try {
        const [results] = await pool.query(sql, [id]);
        if (results.length > 0) {
            res.json({ name: results[0].hap });
        } else {
            res.status(404).send({ message: 'HAP not found' });
        }
    } catch (error) {
        console.error('Error fetching HAP name:', error);
        res.status(500).send({ message: 'Error fetching HAP name', details: error.message });
    }
});

app.post('/api/users/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).send({ message: 'Token and new password are required.' });
    }

    const findUserSql = 'SELECT * FROM users WHERE reset_password_token = ? AND reset_password_expires > NOW()';

    try {
        const [results] = await pool.query(findUserSql, [token]);
        if (results.length === 0) {
            return res.status(400).send({ message: 'Token is invalid or has expired' });
        }

        const user = results[0];
        const userId = user.id;

        // Hash the new password asynchronously
        const hashedPassword = await bcrypt.hash(newPassword, 10); // Use bcrypt with async promise

        // SQL to update the user's password and clear the reset token fields
        const updatePasswordSql = 'UPDATE users SET password = ?, reset_password_token = NULL, reset_password_expires = NULL WHERE id = ?';
        const [updateResults] = await pool.query(updatePasswordSql, [hashedPassword, userId]);

        if (updateResults.affectedRows === 0) {
            return res.status(404).send({ message: 'User not found' });
        }

        res.send({ message: 'Password has been updated successfully' });
    } catch (error) {
        console.error('Error processing reset password:', error);
        res.status(500).send({ message: 'Error updating password', details: error.message });
    }
});

app.post('/api/users/delete', async (req, res) => {
    const { id } = req.body; // Get the ID of the user to delete

    if (!id) {
        return res.status(400).json({ message: 'User ID is required.' });
    }

    try {
        // Assuming 'pool' is your database connection pool that you've previously configured
        const [results] = await pool.query('DELETE FROM users WHERE id = ?', [id]);

        if (results.affectedRows === 0) {
            // No user found with the given ID or no deletion occurred
            return res.status(404).send({ message: 'User not found or no changes made' });
        }

        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ message: 'Error deleting user', details: error.message });
    }
});

app.post('/api/organization/delete', async (req, res) => {
    const { id } = req.body; // Get the ID of the organization to delete

    if (!id) {
        return res.status(400).json({ message: 'Organization ID is required.' });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction(); // Start transaction

        // Delete users associated with the organization first
        const userResults = await connection.query('DELETE FROM users WHERE organization = ?', [id]);
        console.log(`${userResults[0].affectedRows} users deleted.`);

        // Then delete the organization
        const orgResults = await connection.query('DELETE FROM organizations WHERE id = ?', [id]);
        if (orgResults[0].affectedRows === 0) {
            // No organization found with the given ID
            await connection.rollback(); // Rollback transaction
            return res.status(404).send({ message: 'Organization not found' });
        }

        await connection.commit(); // Commit the transaction
        res.json({ message: 'Organization and related users deleted successfully' });
    } catch (error) {
        await connection.rollback(); // Rollback transaction on error
        console.error('Error deleting organization and user(s):', error);
        res.status(500).json({ message: 'Error deleting organization and user(s)', details: error.message });
    } finally {
        connection.release(); // Release connection back to the pool
    }
});

app.get('/api/email-settings/:id', async (req, res) => {
    const { id } = req.params;
    console.log("Fetching email settings for HAP ID:", id); // Confirm ID received

    const sql = 'SELECT * FROM hap WHERE id = ?';
    try {
        const [results] = await pool.query(sql, [id]);
        console.log("Email settings result:", results); // Log the query result
        res.json(results.length > 0 ? results[0] : {});
    } catch (error) {
        console.error('Failed to get email settings:', error);
        res.status(500).send({ message: 'Internal Server Error', details: error.message });
    }
});

app.post('/api/update-email-settings/:id', async (req, res) => {
    const { id } = req.params;
    const { emailAddress, smtpServer, port, password } = req.body;

    try {
        const pw_encrypted = encrypt(password); // Assuming encrypt function returns { iv, encryptedData }
        const sql = 'UPDATE hap SET smtp = ?, port = ?, password_iv = ?, password_encrypted = ?, email_sending = ? WHERE id = ?';

        // Properly capture the results from the database operation
        const [results] = await pool.execute(sql, [
            smtpServer,
            port,
            pw_encrypted.iv,
            pw_encrypted.encryptedData,
            emailAddress,
            id
        ]);

        // Check if any rows were affected
        if (results.affectedRows === 0) {
            // If no rows are affected, it means no record was found with the given ID or no changes were made
            return res.status(404).send('No matching record found or no changes made.');
        }

        res.send('Email settings updated successfully');
    } catch (error) {
        console.error('Failed to update email settings:', error);
        res.status(500).send({ message: 'Internal Server Error', details: error.message });
    }
});

app.get('/api/email-receive-settings/:id', async (req, res) => {
    const { id } = req.params;
    console.log("Fetching email settings for HAP ID:", id); // Confirm ID received

    const sql = 'SELECT * FROM hap WHERE id = ?';
    try {
        const [results] = await pool.query(sql, [id]);
        console.log("Email settings result:", results); // Log the query result
        res.json(results.length > 0 ? results[0] : {});
    } catch (error) {
        console.error('Failed to get email settings:', error);
        res.status(500).send({ message: 'Internal Server Error', details: error.message });
    }
});

app.post('/api/update-email-receive-settings/:id', async (req, res) => {
    const { id } = req.params;
    const { emailReceiveAddress } = req.body;

    const sql = 'UPDATE hap SET `email_receiving` = ? WHERE id = ?';
    try {
        const [results] = await pool.query(sql, [emailReceiveAddress, id]);
        if (results.affectedRows === 0) {
            // If no rows are affected, it might mean the record doesn't exist or no new data was provided
            return res.status(404).send({ message: 'No matching record found or no changes made.' });
        }
        res.send('Email settings updated successfully');
    } catch (error) {
        console.error('Failed to update email settings:', error);
        res.status(500).send({ message: 'Internal Server Error', details: error.message });
    }
});

app.get('/api/org-list/:id', async (req, res) => {
    const { id } = req.params;
    console.log("Fetching organizations for HAP ID:", id); // Confirm ID received

    const sql = 'SELECT id, organization FROM organizations WHERE hap = ?';
    try {
        const [results] = await pool.query(sql, [id]);
        if (results.length > 0) {
            console.log("Organizations result:", results); // Log the query result
            res.json({ organizations: results });
        } else {
            res.status(404).send({ message: 'No organizations found for the given HAP ID' });
        }
    } catch (error) {
        console.error('Failed to get organizations:', error);
        res.status(500).send({ message: 'Internal Server Error', details: error.message });
    }
});

app.get('/api/org-functions/:id', async (req, res) => {
    const { id } = req.params;
    console.log("Fetching organizations for Org ID:", id); // Confirm ID received

    const sql = 'SELECT id, name FROM functions WHERE org = ?';
    try {
        const [results] = await pool.query(sql, [id]);
        if (results.length > 0) {
            console.log("Functions result:", results); // Log the query result
            res.json({ functions: results });
        } else {
            res.status(404).send({ message: 'No functions found for the given Org ID' });
        }
    } catch (error) {
        console.error('Failed to get functions:', error);
        res.status(500).send({ message: 'Internal Server Error', details: error.message });
    }
});

// Serve index.html for root URL
app.get('/', (req, res) => {
   res.sendFile(__dirname + '/index.html');
});

// Start server
app.listen(PORT, () => {
   console.log(`Server running on port ${PORT}`);
});
