const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const { initDb, db } = require('./db');
const moment = require('moment-timezone');
const { v4: uuidv4 } = require('uuid');
const expressLayouts = require('express-ejs-layouts');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3002;

// CONFIGURATIONS
const ADMIN_PANEL_PASSWORD = process.env.ADMIN_PANEL_PASSWORD;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const PAYMONGO_SECRET = process.env.PAYMONGO_SECRET;
// Sa session secret:
secret: process.env.SESSION_SECRET || 'fallback_secret',

// VIEW ENGINE SETUP
app.set('view engine', 'ejs');
app.set('layout', 'layout');
app.set('views', __dirname + '/views');

app.use(express.static(__dirname + '/public'));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// --- SESSION & FLASH CONFIGURATION ---
app.use(
  session({
    secret: 'change_this_secret',
    resave: false, 
    saveUninitialized: false,
    cookie: { maxAge: 600000 }
  })
);

app.use(flash()); 

app.use(passport.initialize());
app.use(passport.session());
app.use(expressLayouts);

// --- GLOBAL VARIABLES FOR TEMPLATES ---
app.use((req, res, next) => {
    res.locals.user = req.user || null;
    
    const successMsg = req.flash('success');
    const errorMsg = req.flash('error');
    
    res.locals.messages = {
        success: successMsg.length > 0 ? successMsg : null,
        error: errorMsg.length > 0 ? errorMsg : null
    };
    next();
});

// Initialize Database
initDb();

// PASSPORT AUTHENTICATION
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Incorrect email.' });
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return done(null, false, { message: 'Incorrect password.' });
        return done(null, user);
    });
}));

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
    db.get('SELECT id, name, email, phone, is_admin, is_controller, balance, gcash_number, name_change_count FROM users WHERE id = ?', [id], (err, user) => {
        done(err, user);
    });
});

// --- HELPERS / MIDDLEWARES ---

function manilaNow() {
    return moment().tz('Asia/Manila');
}

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function ensureAuthenticated(req, res, next) {
    if (!req.isAuthenticated()) return res.redirect('/login');
    if (Number(req.user.is_controller) === 1) return res.redirect('/controller');
    return next();
}

function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user && req.user.is_admin === 1 && req.user.email === ADMIN_EMAIL) {
        return next();
    }
    res.status(403).send('Forbidden: Admin access only');
}

function ensureController(req, res, next) {
    if (req.isAuthenticated() && req.user && Number(req.user.is_controller) === 1) {
        return next();
    }
    res.status(403).send('Forbidden: Controller access only');
}

function ensureAdminPanelAccess(req, res, next) {
    if (!req.session.adminVerified) return res.redirect('/admin-auth');
    next();
}

// --- PROFILE ROUTES ---

app.get('/profile', ensureAuthenticated, (req, res) => {
    db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, userRow) => {
        res.render('profile', { user: userRow }); 
    });
});

app.post('/profile/update-info', ensureAuthenticated, (req, res) => {
    const { name, email, phone } = req.body;
    db.get('SELECT name, name_change_count FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err || !user) {
            req.flash('error', 'Database error.');
            return res.redirect('/profile');
        }
        let newCount = user.name_change_count || 0;
        let finalName = user.name;
        if (name !== user.name) {
            if (newCount >= 2) {
                req.flash('error', 'Hindi na pwedeng palitan ang pangalan. Sagad na sa 2 limits.');
                return res.redirect('/profile');
            }
            newCount++;
            finalName = name; 
        }
        db.run('UPDATE users SET name = ?, email = ?, phone = ?, name_change_count = ? WHERE id = ?', 
        [finalName, email, phone, newCount, req.user.id], (err) => {
            if (err) req.flash('error', 'Error updating profile.');
            else req.flash('success', 'Profile updated successfully!');
            res.redirect('/profile');
        });
    });
});

app.post('/profile/update-payment', ensureAuthenticated, async (req, res) => {
    const { gcash_number, current_password } = req.body;
    db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id], async (err, user) => {
        if (err || !user) { req.flash('error', 'User not found.'); return res.redirect('/profile'); }
        const match = await bcrypt.compare(current_password, user.password_hash);
        if (!match) { req.flash('error', 'Maling password.'); return res.redirect('/profile'); }
        db.run('UPDATE users SET gcash_number = ? WHERE id = ?', [gcash_number, req.user.id], (err) => {
            if (err) req.flash('error', 'Error updating payment details.');
            else req.flash('success', 'GCash number updated!');
            res.redirect('/profile');
        });
    });
});

app.post('/profile/update-password', ensureAuthenticated, async (req, res) => {
    const { current_password, new_password, confirm_password } = req.body;
    if (new_password !== confirm_password) { req.flash('error', 'Passwords do not match.'); return res.redirect('/profile'); }
    db.get('SELECT password_hash FROM users WHERE id = ?', [req.user.id], async (err, user) => {
        if (err || !user) { req.flash('error', 'User not found.'); return res.redirect('/profile'); }
        const match = await bcrypt.compare(current_password, user.password_hash);
        if (!match) { req.flash('error', 'Mali ang current password.'); return res.redirect('/profile'); }
        const hashedPassword = await bcrypt.hash(new_password, 10);
        db.run('UPDATE users SET password_hash = ? WHERE id = ?', [hashedPassword, req.user.id], (err) => {
            if (err) req.flash('error', 'Error updating password.');
            else req.flash('success', 'Password changed successfully!');
            res.redirect('/profile');
        });
    });
});

// --- AUTH ROUTES ---

app.get('/', (req, res) => res.render('index', { user: req.user }));

app.get('/register', (req, res) => res.render('register', { step: 'input' }));

app.post('/register', async (req, res) => {
    const { name, email, phone, password } = req.body;
    if (!name || !email || !phone || !password) { req.flash('error', 'Lahat ng fields ay kailangan.'); return res.redirect('/register'); }
    db.get('SELECT id FROM users WHERE email = ? OR phone = ?', [email, phone], async (err, row) => {
        if (row) { req.flash('error', 'Email o Phone number ay gamit na.'); return res.redirect('/register'); }
        const otp = generateOTP();
        const hashedPassword = await bcrypt.hash(password, 10);
        req.session.tempUser = { name, email, phone, password_hash: hashedPassword, otp: otp };
        console.log(`OTP: ${otp}`);
        res.render('register', { step: 'verify', phone: phone });
    });
});

app.post('/verify-otp', (req, res) => {
    const { otp_input } = req.body;
    const tempUser = req.session.tempUser;
    if (!tempUser) { req.flash('error', 'Session expired.'); return res.redirect('/register'); }
    if (otp_input === tempUser.otp) {
        db.run('INSERT INTO users (name, email, phone, password_hash, balance, is_admin) VALUES (?,?,?,?,0,0)',
            [tempUser.name, tempUser.email, tempUser.phone, tempUser.password_hash], (err) => {
                if (err) { req.flash('error', 'Error saving user.'); return res.redirect('/register'); }
                delete req.session.tempUser; 
                req.flash('success', 'Account created! Login na.');
                res.redirect('/login');
            });
    } else {
        req.flash('error', 'Maling OTP.');
        res.render('register', { step: 'verify', phone: tempUser.phone });
    }
});

app.get('/login', (req, res) => res.render('login'));
app.post('/login', passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }), (req, res) => {
    if (Number(req.user.is_controller) === 1) return res.redirect('/controller');
    if (req.user.is_admin === 1) return res.redirect('/admin');
    res.redirect('/dashboard');
});

app.get('/logout', logoutHandler);
app.post('/logout', logoutHandler);
function logoutHandler(req, res) {
    req.logout(() => { req.session.destroy(() => res.redirect('/')); });
}

// --- USER DASHBOARD & TRANSACTIONS ---

app.get('/dashboard', ensureAuthenticated, (req, res) => {
    db.all('SELECT * FROM bets WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err, bets) => {
        db.all('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC', [req.user.id], (err2, txs) => {
            db.all('SELECT amount FROM bets', [], (err3, allBets) => {
                let jackpot = 100000;
                allBets.forEach(b => jackpot += b.amount * 0.02);
                db.get('SELECT * FROM results ORDER BY created_at DESC LIMIT 1', [], (err4, result) => {
                    let userWon = false;
                    if (bets && result) {
                        const rnums = result.numbers.split(',').map(Number).sort((a,b)=>a-b);
                        bets.forEach(b => {
                            if(b.numbers){
                                const bnums = b.numbers.split(',').map(Number).sort((a,b)=>a-b);
                                if (JSON.stringify(bnums) === JSON.stringify(rnums)) userWon = true;
                            }
                        });
                    }
                    res.render('dashboard', { user: req.user, bets, txs, jackpot, result, userWon });
                });
            });
        });
    });
});

app.get('/topup', ensureAuthenticated, (req, res) => res.render('topup', { user: req.user }));
app.post('/topup', ensureAuthenticated, (req, res) => {
    const { amount, reference } = req.body;
    if (!amount || amount <= 0) { req.flash('error','Invalid amount'); return res.redirect('/topup'); }
    db.run('INSERT INTO transactions (id,user_id,type,amount,status,reference,created_at) VALUES (?,?,?,?,?,?,?)', 
    [uuidv4(), req.user.id, 'topup', amount, 'pending', reference || '', new Date().toISOString()], () => {
        req.flash('success','Top-up request created.');
        res.redirect('/dashboard');
    });
});

app.get('/withdraw', ensureAuthenticated, (req, res) => res.render('withdraw', { user: req.user }));
app.post('/withdraw', ensureAuthenticated, (req, res) => {
    const { amount } = req.body;
    const a = parseFloat(amount);
    if (!a || a <= 0) { req.flash('error','Invalid amount'); return res.redirect('/withdraw'); }
    db.get('SELECT balance, gcash_number FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (!user.gcash_number) { req.flash('error', 'Set GCash number in Profile.'); return res.redirect('/profile'); }
        if (user.balance < a) { req.flash('error', 'Insufficient balance'); return res.redirect('/withdraw'); }
        db.run('INSERT INTO transactions (id,user_id,type,amount,status,reference,created_at) VALUES (?,?,?,?,?,?,?)', 
        [uuidv4(), req.user.id, 'withdraw', a, 'pending', user.gcash_number, new Date().toISOString()], () => {
            db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [a, req.user.id], () => {
                req.flash('success','Withdraw request created.');
                res.redirect('/dashboard');
            });
        });
    });
});

app.get('/bet', ensureAuthenticated, (req, res) => res.render('bet', { user: req.user }));
app.post('/bet', ensureAuthenticated, (req, res) => {
    const dow = manilaNow().day();
    if (dow === 0 || dow === 6) { req.flash('error','Bets allowed Mon-Fri only'); return res.redirect('/bet'); }
    const numsRaw = Array.isArray(req.body.numbers) ? req.body.numbers : (req.body.numbers || '').split(',');
    const nums = numsRaw.map(n=>parseInt(n)).filter(n=>!isNaN(n));
    if (nums.length !== 6) { req.flash('error','Choose 6 numbers'); return res.redirect('/bet'); }
    const price = 10;
    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (row.balance < price) { req.flash('error','Insufficient balance'); return res.redirect('/topup'); }
        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [price, req.user.id], () => {
            db.run('INSERT INTO bets (user_id,numbers,amount,status,game_type,created_at) VALUES (?,?,?,?,?,?)', 
            [req.user.id, nums.join(','), price, 'pending', 'lotto', new Date().toISOString()], () => {
                req.flash('success','Bet placed!');
                res.redirect('/dashboard');
            });
        });
    });
});

// --- ADMIN ROUTES ---

app.get('/admin-auth', (req, res) => res.render('admin_auth'));
app.post('/admin-auth', ensureAuthenticated, (req, res) => {
    if (req.body.admin_password !== ADMIN_PANEL_PASSWORD) { req.flash('error', 'Incorrect password'); return res.redirect('/admin-auth'); }
    req.session.adminVerified = true;
    res.redirect('/admin');
});

app.get('/admin', ensureAdmin, ensureAdminPanelAccess, (req, res) => {
    db.all('SELECT * FROM bets ORDER BY created_at DESC', [], (err, bets) => {
        db.all('SELECT * FROM transactions ORDER BY created_at DESC', [], (err2, txs) => {
            db.all('SELECT id,name,email,phone,balance,is_admin,gcash_number FROM users', [], (err3, users) => {
                const totalBetsAmount = bets.reduce((sum, b) => sum + (b.amount || 0), 0);
                const totalPayouts = txs.filter(t => t.type === 'payout' || (t.type === 'withdraw' && t.status === 'paid')).reduce((sum, t) => sum + (t.amount || 0), 0);
                const houseEarnings = totalBetsAmount - totalPayouts;
                req.sessionStore.all((err, sessions) => {
                    let onlineCount = (sessions) ? Object.values(sessions).filter(s => s.passport && s.passport.user).length : 0;
                    res.render('admin', { user: req.user, bets, txs, users, houseEarnings, totalBetsAmount, onlinePlayers: onlineCount });
                });
            });
        });
    });
});

// --- NEW ADMIN UPDATE USER ROUTE ---
app.post('/admin/user/update', ensureAdmin, async (req, res) => {
    const { id, name, email, phone, gcash_number, new_password } = req.body;
    try {
        if (new_password && new_password.trim() !== "") {
            const hashedPassword = await bcrypt.hash(new_password, 10);
            db.run('UPDATE users SET name = ?, email = ?, phone = ?, gcash_number = ?, password_hash = ? WHERE id = ?',
                [name, email, phone, gcash_number, hashedPassword, id], (err) => {
                    if (err) req.flash('error', 'Error updating user with password.');
                    else req.flash('success', 'User updated successfully (including password).');
                    res.redirect('/admin');
                });
        } else {
            db.run('UPDATE users SET name = ?, email = ?, phone = ?, gcash_number = ? WHERE id = ?',
                [name, email, phone, gcash_number, id], (err) => {
                    if (err) req.flash('error', 'Error updating user info.');
                    else req.flash('success', 'User info updated successfully.');
                    res.redirect('/admin');
                });
        }
    } catch (error) { req.flash('error', 'Server error.'); res.redirect('/admin'); }
});

app.post('/admin/tx/confirm', ensureAdmin, (req,res)=>{
    db.get('SELECT * FROM transactions WHERE id = ?', [req.body.id], (err, tx)=>{
        if (tx && tx.status === 'pending') {
            db.run('UPDATE transactions SET status = ? WHERE id = ?', ['confirmed', tx.id], () => {
                db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [tx.amount, tx.user_id], () => {
                    req.flash('success','Topup confirmed');
                    res.redirect('/admin');
                });
            });
        }
    });
});

app.post('/admin/tx/complete', ensureAdmin, (req,res)=>{
    db.run('UPDATE transactions SET status = ? WHERE id = ?', ['paid', req.body.id], () => {
        req.flash('success','Withdraw marked as paid');
        res.redirect('/admin');
    });
});

app.get('/admin/result', ensureAdmin, (req,res)=> res.render('enter_result', { user: req.user }));
app.post('/admin/result', ensureAdmin, (req,res)=>{
    const nums = (req.body.numbers||'').split(',').map(n=>parseInt(n)).filter(n=>!isNaN(n));
    if (nums.length !== 6) return res.redirect('/admin/result');
    const resultId = uuidv4();
    db.run('INSERT INTO results (id,numbers,created_at) VALUES (?,?,?)', [resultId, nums.join(','), new Date().toISOString()], () => {
        db.all('SELECT * FROM bets WHERE status = "pending" AND (game_type="lotto" OR numbers IS NOT NULL)', [], (err, bets)=>{
            bets.forEach(b => {
                const bnums = b.numbers.split(',').map(Number).sort((a,b)=>a-b);
                const rnums = nums.slice().sort((a,b)=>a-b);
                if (JSON.stringify(bnums) === JSON.stringify(rnums)) {
                    const prize = b.amount * 100;
                    db.run('INSERT INTO transactions (id,user_id,type,amount,status,reference,created_at) VALUES (?,?,?,?,?,?,?)', 
                    [uuidv4(), b.user_id, 'payout', prize, 'confirmed', 'win:'+resultId, new Date().toISOString()]);
                    db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [prize, b.user_id]);
                    db.run('UPDATE bets SET status = "won" WHERE id = ?', [b.id]);
                } else {
                    db.run('UPDATE bets SET status = "lost" WHERE id = ?', [b.id]);
                }
            });
            res.redirect('/admin');
        });
    });
});

// --- SABONG ROUTES ---

app.get('/sabong', ensureAuthenticated, (req, res) => {
    db.get("SELECT value FROM settings WHERE key = 'live_stream_url'", (err, stream) => {
        db.get("SELECT value FROM settings WHERE key = 'video_status'", (err2, status) => {
            res.render('online_sabong', { 
                user: req.user, 
                streamUrl: stream ? stream.value : '',
                videoStatus: status ? status.value : 'playing'
            });
        });
    });
});

app.post('/bet/sabong', ensureAuthenticated, (req, res) => {
    const { amount, choice } = req.body; 
    const betAmount = parseFloat(amount);
    if (betAmount <= 0 || isNaN(betAmount)) return res.status(400).json({ error: 'Invalid amount' });
    db.get('SELECT balance FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (row.balance < betAmount) return res.status(400).json({ error: 'Insufficient balance' });
        db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [betAmount, req.user.id], () => {
            db.run('INSERT INTO bets (user_id, amount, choice, game_type, status, created_at) VALUES (?, ?, ?, ?, ?, ?)', 
            [req.user.id, betAmount, choice, 'sabong', 'pending', new Date().toISOString()], () => {
                res.json({ message: `Bet placed on ${choice}!`, newBalance: row.balance - betAmount });
            });
        });
    });
});

app.post('/controller/sabong-result', ensureController, (req, res) => {
    const winner = (req.body.winner || '').toUpperCase();

    if (!['MERON', 'WALA'].includes(winner)) {
        return res.redirect('/controller');
    }

    db.all("SELECT * FROM bets WHERE game_type = 'sabong' AND status = 'pending'", [], (err, allBets) => {

        if (!allBets || allBets.length === 0) return res.redirect('/controller');

        const totalPool = allBets.reduce((sum, b) => sum + b.amount, 0);
        const winners = allBets.filter(b => b.choice.toUpperCase() === winner);

        const houseCut = totalPool * 0.20;
        const distributable = totalPool * 0.80;

        if (winners.length > 0) {
            const totalWinnerBet = winners.reduce((sum, b) => sum + b.amount, 0);

            winners.forEach(bet => {
                const payout = (bet.amount / totalWinnerBet) * distributable;

                db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [payout, bet.user_id]);
                db.run('UPDATE bets SET status = "won", payout = ? WHERE id = ?', [payout, bet.id]);

                db.run('INSERT INTO transactions (id,user_id,type,amount,status,reference,created_at) VALUES (?,?,?,?,?,?,?)',
                    [uuidv4(), bet.user_id, 'payout', payout, 'confirmed', 'sabong_win', new Date().toISOString()]
                );
            });
        }

        // losers
        db.run("UPDATE bets SET status = 'lost' WHERE game_type='sabong' AND status='pending' AND choice != ?", [winner]);

        // save result
        db.run("INSERT INTO results (id,numbers,created_at) VALUES (?,?,?)",
            [uuidv4(), winner, new Date().toISOString()]
        );

        res.redirect('/controller');
    });
});

app.post('/controller/draw-result', ensureController, (req, res) => {
    const nums = (req.body.numbers || '')
        .split(',')
        .map(n => parseInt(n))
        .filter(n => !isNaN(n));

    if (nums.length !== 6) return res.redirect('/controller');

    const resultId = uuidv4();

    db.run('INSERT INTO results (id,numbers,created_at) VALUES (?,?,?)',
        [resultId, nums.join(','), new Date().toISOString()],
        () => {

       db.all("SELECT * FROM bets WHERE game_type='lotto' AND status='pending'", [], (err, bets) => {

    if (err) {
        console.log(err);
        return res.redirect('/controller');
    }

    if (!bets || bets.length === 0) {
        return res.redirect('/controller');
    }

            bets.forEach(b => {
                const bnums = b.numbers.split(',').map(Number).sort();
                const rnums = nums.slice().sort();

                if (JSON.stringify(bnums) === JSON.stringify(rnums)) {
                    const prize = b.amount * 100;

                    db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [prize, b.user_id]);
                    db.run('UPDATE bets SET status="won" WHERE id=?', [b.id]);

                    db.run('INSERT INTO transactions (id,user_id,type,amount,status,reference,created_at) VALUES (?,?,?,?,?,?,?)',
                        [uuidv4(), b.user_id, 'payout', prize, 'confirmed', 'lotto_win', new Date().toISOString()]
                    );
                } else {
                    db.run('UPDATE bets SET status="lost" WHERE id=?', [b.id]);
                }
            });

            res.redirect('/controller');
        });
    });
});


app.post('/admin/video/update', ensureAdmin, (req, res) => {
    let { url, status } = req.body;
    if (url.includes('watch?v=')) url = url.replace('watch?v=', 'embed/');
    else if (url.includes('youtu.be/')) url = url.replace('youtu.be/', 'www.youtube.com/embed/');
    if (url.includes('?')) url = url.split('?')[0];
    url += "?controls=0&disablekb=1&rel=0&autoplay=1&modestbranding=1&iv_load_policy=3";
    db.run("UPDATE settings SET value = ? WHERE key = 'live_stream_url'", [url], () => {
        db.run("UPDATE settings SET value = ? WHERE key = 'video_status'", [status], () => {
            res.redirect('/admin');
        });
    });
});

app.post('/paymongo/gcash', ensureAuthenticated, async (req, res) => {
    try {
        const response = await axios.post('https://api.paymongo.com/v1/links', {
            data: { attributes: { amount: req.body.amount * 100, description: 'Top-up', metadata: { user_id: req.user.id } } }
        }, {
            headers: { Authorization: 'Basic ' + Buffer.from(PAYMONGO_SECRET + ':').toString('base64'), 'Content-Type': 'application/json' }
        });
        res.redirect(response.data.data.attributes.checkout_url);
    } catch (err) { res.redirect('/topup'); }
});

app.post('/paymongo/webhook', (req, res) => {
    const event = req.body;
    if (event.data.attributes.type === 'payment.paid') {
        const payment = event.data.attributes.data.attributes;
        const amount = payment.amount / 100;
        const userId = payment.metadata.user_id;
        db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, userId], () => {
            db.run('INSERT INTO transactions (id,user_id,type,amount,status,reference,created_at) VALUES (?,?,?,?,?,?,?)', 
            [uuidv4(), userId, 'topup', amount, 'confirmed', event.data.attributes.data.id, new Date().toISOString()]);
        });
    }
    res.sendStatus(200);
});

app.get('/controller', ensureController, (req, res) => {
    db.all('SELECT * FROM bets ORDER BY created_at DESC', [], (err, bets) => {

        db.get("SELECT value FROM settings WHERE key = 'live_stream_url'", (err2, stream) => {

            res.render('controller', {
                user: req.user,
                bets,
                streamUrl: stream ? stream.value : ''
            });

        });

    });
});

// --- HOUSE LEDGER ROUTE (FIXED) ---
app.get('/admin/house-ledger', ensureAdmin, ensureAdminPanelAccess, (req, res) => {
    // Kunin lahat ng Sabong Bets
    db.all("SELECT * FROM bets WHERE game_type = 'sabong' AND status != 'pending'", [], (err, sabongBets) => {
        // Kunin lahat ng Lotto/Draw bets
        db.all("SELECT * FROM bets WHERE game_type = 'lotto'", [], (err2, drawBets) => {
            
            // Siguraduhin na hindi undefined ang mga arrays (Fallback to empty array)
            const sBets = sabongBets || [];
            const dBets = drawBets || [];

            // LOGIC PARA SA SABONG EARNINGS (20%)
            // Gagamit tayo ng safe check bago mag reduce
            let totalSabongVolume = sBets.reduce((sum, b) => sum + (Number(b.amount) || 0), 0);
            let sabongEarnings = totalSabongVolume * 0.20;

            // LOGIC PARA SA DRAW EARNINGS (10 pesos flat fee per bet)
            let totalDrawBets = dBets.length;
            let drawEarnings = totalDrawBets * 10;

            let totalHouseEarnings = sabongEarnings + drawEarnings;

            res.render('houseledger', { 
                user: req.user,
                sabongBets: sBets,
                drawBets: dBets,
                sabongEarnings,
                drawEarnings,
                totalHouseEarnings,
                totalSabongVolume
            });
        });
    });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));