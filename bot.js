require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const QRCode = require('qrcode');
const { Telegraf, Markup, session } = require('telegraf');
const {
  Connection,
  PublicKey,
  Keypair,
  Transaction,
  SystemProgram,
  LAMPORTS_PER_SOL
} = require('@solana/web3.js');
const {
  getOrCreateAssociatedTokenAccount,
  createTransferInstruction,
  TOKEN_PROGRAM_ID
} = require('@solana/spl-token');
const admin = require('firebase-admin');
const bs58 = require('bs58');
const moment = require('moment-timezone');

// ----------------- Environment & Encryption Setup -----------------
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY) {
  console.error('ENCRYPTION_KEY environment variable is not set.');
  process.exit(1);
}
if (Buffer.from(ENCRYPTION_KEY, 'hex').length !== 32) {
  console.error('ENCRYPTION_KEY must be a 32-byte key in hex format.');
  process.exit(1);
}
const ALGORITHM = 'aes-256-cbc';

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedText) {
  const textParts = encryptedText.split(':');
  const iv = Buffer.from(textParts.shift(), 'hex');
  const encrypted = textParts.join(':');
  const decipher = crypto.createDecipheriv(ALGORITHM, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ----------------- Enhanced SAP Configuration -----------------
const SAP_MIN_LENGTH = 8;
const SAP_MAX_ATTEMPTS = 3;
const SAP_COOLDOWN_MINUTES = 15;
const SAP_SPECIAL_CHARS = '!@#$%^&*(),.?":{}|<>';

// Helper function to validate SAP strength
function validateSAPStrength(sap) {
  if (sap.length < SAP_MIN_LENGTH) {
    return { valid: false, message: `SAP must be at least ${SAP_MIN_LENGTH} characters long` };
  }
  if (!/[A-Z]/.test(sap)) {
    return { valid: false, message: 'SAP must contain at least one uppercase letter' };
  }
  if (!/[a-z]/.test(sap)) {
    return { valid: false, message: 'SAP must contain at least one lowercase letter' };
  }
  if (!/\d/.test(sap)) {
    return { valid: false, message: 'SAP must contain at least one number' };
  }
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(sap)) {
    return { valid: false, message: 'SAP must contain at least one special character' };
  }
  return { valid: true };
}

// Enhanced SAP storage with additional hashing
async function setUserSAP(userId, sap) {
  // First validate the SAP
  const validation = validateSAPStrength(sap);
  if (!validation.valid) {
    throw new Error(validation.message);
  }

  // Create a hash of the SAP for additional security
  const sapHash = crypto.createHash('sha256').update(sap).digest('hex');
  
  // Then encrypt the original SAP
  const encryptedSap = encrypt(sap);

  const userRef = db.collection('users').doc(userId.toString());
  await userRef.set({ 
    sap: encryptedSap,
    sapHash, // Store hash for verification without decrypting
    sapAttempts: 0, // Initialize attempt counter
    sapLastAttempt: null,
    sapLockedUntil: null
  }, { merge: true });
}

// Enhanced SAP verification with attempt tracking
async function verifyUserSAP(userId, sapAttempt) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  
  if (!userDoc.exists) return false;
  const userData = userDoc.data();
  
  // Check if SAP is locked
  if (userData.sapLockedUntil && new Date(userData.sapLockedUntil) > new Date()) {
    const lockTime = moment(userData.sapLockedUntil).fromNow();
    throw new Error(`Too many failed attempts. Try again ${lockTime}`);
  }
  
  // First verify using the hash for faster verification
  const attemptHash = crypto.createHash('sha256').update(sapAttempt).digest('hex');
  if (attemptHash !== userData.sapHash) {
    // Increment failed attempts
    const newAttempts = (userData.sapAttempts || 0) + 1;
    let updateData = {
      sapAttempts: newAttempts,
      sapLastAttempt: admin.firestore.FieldValue.serverTimestamp()
    };
    
    // Lock if too many attempts
    if (newAttempts >= SAP_MAX_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + SAP_COOLDOWN_MINUTES * 60 * 1000);
      updateData.sapLockedUntil = lockUntil;
    }
    
    await userRef.update(updateData);
    return false;
  }
  
  // If hash matches, verify with the encrypted version
  const storedSAP = decrypt(userData.sap);
  if (storedSAP !== sapAttempt) {
    // This shouldn't happen if hashes match, but just in case
    await userRef.update({
      sapAttempts: admin.firestore.FieldValue.increment(1),
      sapLastAttempt: admin.firestore.FieldValue.serverTimestamp()
    });
    return false;
  }
  
  // Reset attempts on successful verification
  await userRef.update({
    sapAttempts: 0,
    sapLockedUntil: null,
    sapLastAttempt: admin.firestore.FieldValue.serverTimestamp()
  });
  
  return true;
}

// Enhanced SAP verification prompt
async function requireSAPVerification(ctx, actionName, callbackData = null) {
  const userId = ctx.from.id;
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  
  if (!userDoc.exists || !userDoc.data().sap) {
    await ctx.reply(
      `🔒 <b>SAP Not Set</b>\n\nYou must set a Secure Action Password before performing this action.\n\nPlease set your SAP first in Settings.`,
      { parse_mode: 'HTML' }
    );
    return false;
  }
  
  const userData = userDoc.data();
  
  // Check if SAP is locked
  if (userData.sapLockedUntil && new Date(userData.sapLockedUntil) > new Date()) {
    const lockTime = moment(userData.sapLockedUntil).fromNow();
    await ctx.reply(
      `🔒 <b>SAP Locked</b>\n\nToo many failed attempts. Try again ${lockTime}.`,
      { parse_mode: 'HTML' }
    );
    return false;
  }
  
  ctx.session.awaitingSAP = {
    action: actionName,
    attempts: userData.sapAttempts || 0,
    callbackData: callbackData,
    messageIds: [] // To track messages to delete
  };
  
  const sapMessage = await ctx.reply(
    `🔒 <b>SAP Verification Required</b>\n\nTo ${actionName}, please enter your Secure Action Password (${ctx.session.awaitingSAP.attempts + 1}/${SAP_MAX_ATTEMPTS} attempts):`,
    { parse_mode: 'HTML' }
  );
  
  ctx.session.awaitingSAP.messageIds.push(sapMessage.message_id);
  return true;
}

// ----------------- Local Private Keys Storage -----------------
const PRIVATE_KEYS_FILE = path.join(__dirname, 'privateKeys.json');

function loadLocalPrivateKeys() {
  if (!fs.existsSync(PRIVATE_KEYS_FILE)) return {};
  const data = fs.readFileSync(PRIVATE_KEYS_FILE);
  try {
    return JSON.parse(data);
  } catch (error) {
    console.error('Error parsing local private keys file:', error);
    return {};
  }
}

function saveLocalPrivateKeys(keys) {
  fs.writeFileSync(PRIVATE_KEYS_FILE, JSON.stringify(keys, null, 2));
}

function setLocalPrivateKey(walletId, privateKey) {
  const keys = loadLocalPrivateKeys();
  const encryptedKey = encrypt(privateKey);
  keys[walletId] = encryptedKey;
  saveLocalPrivateKeys(keys);
}

function getLocalPrivateKey(walletId) {
  const keys = loadLocalPrivateKeys();
  const encryptedKey = keys[walletId];
  if (!encryptedKey) return null;
  return decrypt(encryptedKey);
}

function removeLocalPrivateKey(walletId) {
  const keys = loadLocalPrivateKeys();
  delete keys[walletId];
  saveLocalPrivateKeys(keys);
}

// ----------------- Helper for Base58 Decoding -----------------
function decodeBase58(str) {
  if (typeof bs58.decode === 'function') return bs58.decode(str);
  if (bs58.default && typeof bs58.default.decode === 'function') return bs58.default.decode(str);
  throw new Error('Base58 decode function not available.');
}

// ----------------- FARASbot MINT Address -----------------
const FARASBOT_MINT = new PublicKey(process.env.FARASBOT_MINT_ADDRESS || "4hZ8iCL6Tz17J84UBaAdhCTeq96k45k6Ety7wBWB9Dra");

// ----------------- Transfer FARASbot Function -----------------
async function transferFARASbot(bonusAmount, userPublicKey) {
  try {
    const decimals = 9;
    const integerAmount = Math.round(bonusAmount * 10 ** decimals);

    const fromTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      botKeypair,
      FARASBOT_MINT,
      botKeypair.publicKey
    );

    const toTokenAccount = await getOrCreateAssociatedTokenAccount(
      connection,
      botKeypair,
      FARASBOT_MINT,
      new PublicKey(userPublicKey)
    );

    const transaction = new Transaction().add(
      createTransferInstruction(
        fromTokenAccount.address,
        toTokenAccount.address,
        botKeypair.publicKey,
        integerAmount,
        [],
        TOKEN_PROGRAM_ID
      )
    );

    const signature = await connection.sendTransaction(transaction, [botKeypair]);
    console.log("✅ FARASbot Transfer successful. Sig:", signature);
    return signature;
  } catch (error) {
    console.error("❌ transferFARASbot Error:", error);
    throw error;
  }
}

// ----------------- Helper Functions -----------------
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function withTimeout(promise, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Operation timed out after ${ms} ms`));
    }, ms);
    promise.then((res) => {
      clearTimeout(timer);
      resolve(res);
    }).catch((err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ----------------- Firebase Initialization -----------------
const serviceAccount = require("./solana-farasbot-473de-firebase-adminsdk-fbsvc-577282dfdd.json");
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});
const db = admin.firestore();

// ----------------- Solana Connection -----------------
const connection = new Connection(process.env.SOLANA_RPC_URL, 'confirmed');

// ----------------- Global Subscriptions -----------------
const subscriptions = {};

// ----------------- Admin Configuration -----------------
const ADMINS = process.env.ADMINS ? process.env.ADMINS.split(',').map(Number) : [];

// ----------------- Telegram Bot Initialization -----------------
const bot = new Telegraf(process.env.TELEGRAM_BOT_TOKEN);
bot.use(session());
bot.use((ctx, next) => {
  ctx.session = ctx.session || {};
  return next();
});

// ----------------- BOT Wallet Fallback Using BOT_WALLET_SECRET -----------------
let botKeypair;
try {
  botKeypair = Keypair.fromSecretKey(
    new Uint8Array(JSON.parse(process.env.BOT_WALLET_SECRET))
  );
} catch (error) {
  console.error('Error initializing BOT Keypair:', error);
  process.exit(1);
}

async function botWalletHasSufficientSOL(requiredSol) {
  const balance = await connection.getBalance(botKeypair.publicKey);
  const balanceSOL = balance / LAMPORTS_PER_SOL;
  return balanceSOL >= requiredSol;
}

async function transferFromBotWallet(solAmount, destinationAddress) {
  const toPublicKey = new PublicKey(destinationAddress);
  const lamports = Math.round(solAmount * LAMPORTS_PER_SOL);
  const transaction = new Transaction().add(
    SystemProgram.transfer({
      fromPubkey: botKeypair.publicKey,
      toPubkey: toPublicKey,
      lamports,
    })
  );
  const signature = await connection.sendTransaction(transaction, [botKeypair], { preflightCommitment: 'finalized' });
  console.log("BOT wallet transfer successful, signature:", signature);
  return {
    acquiredSol: solAmount,
    withdrawalFee: 0,
    netSol: solAmount,
    withdrawalId: signature,
  };
}

// ----------------- Enhanced Fee Management System -----------------
let currentFee = 0.02; // Initial fee is set to 2%

// Command to change fee percentage - REMOVED SAP REQUIREMENT FOR ADMINS
bot.command('setfee', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins have permission to use this command.');
      return;
    }

    const message = ctx.message.text.replace('/setfee', '').trim();
    const newFee = parseFloat(message);

    if (isNaN(newFee) || newFee <= 0 || newFee > 1) {
      await ctx.reply('❌ Invalid fee percentage. Please provide a value between 0 and 1 (e.g., 0.02 for 2%).');
      return;
    }

    // Save the new fee to database for persistence
    const feeRef = db.collection('system').doc('fee_settings');
    await feeRef.set({
      currentFee: newFee,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: userId
    }, { merge: true });

    currentFee = newFee; // Update the in-memory fee value
    await ctx.reply(`✅ Fee has been updated to ${(currentFee * 100).toFixed(2)}%`);
    
    // Log the fee change
    await db.collection('fee_logs').add({
      previousFee: currentFee,
      newFee: newFee,
      changedBy: userId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      reason: ctx.message.text.split(' ').slice(2).join(' ') || 'No reason provided'
    });
    
  } catch (error) {
    console.error('❌ Set Fee Error:', error);
    await ctx.reply('❌ An error occurred while updating the fee. Please check logs.');
  }
});

// Command to view current fee
bot.command('fee', async (ctx) => {
  try {
    const feeMessage = `ℹ️ <b>Current Fee Structure</b>\n\n` +
      `• Standard Fee: ${(currentFee * 100).toFixed(2)}%\n` +
      `• VIP Users: ${(currentFee * 0.5 * 100).toFixed(2)}%\n` +
      `• Referral Bonus: 25% of fees (first month)\n\n` +
      `Fees are automatically deducted from transactions.`;
    
    await ctx.reply(feeMessage, { parse_mode: 'HTML' });
  } catch (error) {
    console.error('❌ Fee Command Error:', error);
    await ctx.reply('❌ An error occurred while fetching fee information.');
  }
});

// Command to view fee details and statistics
// Command to view fee details and statistics
bot.command('fees', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const isAdmin = ADMINS.includes(userId);

    const message = ctx.message.text.replace('/fees', '').trim();
    let startDate = null;
    let endDate = null;

    // Parse date range if provided
    if (message) {
      const dates = message.split(' ');
      if (dates.length === 2) {
        startDate = new Date(dates[0]);
        endDate = new Date(dates[1]);

        if (isNaN(startDate) || isNaN(endDate)) {
          await ctx.reply('❌ Invalid date format. Use format: /fees <start_date> <end_date> (e.g., /fees 2023-06-01 2023-06-20)');
          return;
        }

        // Add time to end date to include full day
        endDate.setHours(23, 59, 59, 999);
      }
    }

    // Get transactions and calculate fees for the given date range
    let query = db.collection('transactions');

    if (startDate) {
      query = query.where('timestamp', '>=', startDate);
    }
    if (endDate) {
      query = query.where('timestamp', '<=', endDate);
    }

    if (!isAdmin) {
      query = query.where('userId', '==', userId.toString());
    }

    const transactionsSnapshot = await query.get();

    let totalFeesSol = 0;
    let totalFeesUSD = 0;
    let totalTransactions = 0;
    let totalAmount = 0;
    const feeStats = {};
    const userStats = {};

    transactionsSnapshot.forEach(doc => {
      const transaction = doc.data();
      const type = transaction.type || 'unknown';
      const userId = transaction.userId;
      const transactionAmount = transaction.amountSOL || 0;
      const amountUSD = transaction.amountUSD || 0;

      totalTransactions++;

      if (type === 'cash_buy' && amountUSD > 0) {
        const feeUSD = amountUSD * currentFee;
        totalFeesUSD += feeUSD;
        totalAmount += amountUSD;
        feeStats[type] = (feeStats[type] || 0) + feeUSD;

        if (isAdmin) {
          userStats[userId] = (userStats[userId] || 0) + feeUSD;
        }
      } else {
        const feeSOL = transactionAmount * currentFee;
        totalFeesSol += feeSOL;
        totalAmount += transactionAmount;
        feeStats[type] = (feeStats[type] || 0) + feeSOL;

        if (isAdmin) {
          userStats[userId] = (userStats[userId] || 0) + feeSOL;
        }
      }
    });

    // Format fee stats by type
    let feeStatsText = '';
    for (const [type, amount] of Object.entries(feeStats)) {
      const isUSD = type === 'cash_buy';
      feeStatsText += `• ${type}: ${isUSD ? `$${amount.toFixed(2)}` : `${amount.toFixed(4)} SOL`}\n`;
    }

    // Prepare response message
    let response = `💸 <b>Fee Statistics</b>\n\n`;
    response += `📅 Period: ${startDate ? startDate.toLocaleDateString() : 'All time'} to ${endDate ? endDate.toLocaleDateString() : 'Now'}\n`;
    response += `📊 Total Transactions: ${totalTransactions}\n`;
    response += `💰 Total Amount: ${totalAmount.toFixed(2)} (USD & SOL combined)\n`;
    response += `💳 Total Fees Collected:\n   - 💵 USD: $${totalFeesUSD.toFixed(2)}\n   - 🪙 SOL: ${totalFeesSol.toFixed(4)} SOL\n`;
    response += `📝 Current Fee Percentage: ${(currentFee * 100).toFixed(2)}%\n\n`;
    response += `📌 <b>Fee Breakdown by Type</b>\n${feeStatsText}`;

    // Add user breakdown for admins
    if (isAdmin) {
      response += `\n👥 <b>Top Users by Fees Paid</b>\n`;
      const sortedUsers = Object.entries(userStats)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

      for (const [userId, amount] of sortedUsers) {
        response += `• User ${userId}: ${amount.toFixed(4)} ${amount > 1 ? 'USD/SOL' : ''}\n`;
      }
    }

    await ctx.reply(response, { parse_mode: 'HTML' });

  } catch (error) {
    console.error('❌ Fees Command Error:', error);
    await ctx.reply('❌ An error occurred while fetching fee statistics. Please check logs.');
  }
});


// Command to view fee change history
bot.command('feelog', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins have permission to view fee logs.');
      return;
    }

    const message = ctx.message.text.replace('/feelog', '').trim();
    let limit = 10;
    
    if (message && !isNaN(parseInt(message))) {
      limit = parseInt(message);
      if (limit > 50) limit = 50;
    }

    const logs = await db.collection('fee_logs')
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .get();
    
    let logText = '📝 <b>Recent Fee Changes</b>\n\n';
    logs.forEach(doc => {
      const log = doc.data();
      logText += `🕒 ${log.timestamp.toDate().toLocaleString()}\n` +
                 `🔄 ${(log.previousFee * 100).toFixed(2)}% → ${(log.newFee * 100).toFixed(2)}%\n` +
                 `👤 Changed by: ${log.changedBy}\n` +
                 `📝 Reason: ${log.reason || 'Not specified'}\n\n`;
    });
    
    await ctx.reply(logText, { parse_mode: 'HTML' });
  } catch (error) {
    console.error('Fee log error:', error);
    await ctx.reply('❌ Could not retrieve fee logs.');
  }
});

// Command to set fee exemptions
bot.command('setfeeexempt', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins have permission to set fee exemptions.');
      return;
    }

    const args = ctx.message.text.split(' ').slice(1);
    if (args.length < 2) {
      await ctx.reply('❌ Usage: /setfeeexempt <user_id> <true/false>');
      return;
    }

    const targetUserId = args[0];
    const exemptStatus = args[1].toLowerCase() === 'true';

    // Require SAP verification for admin actions
    const sapVerified = await requireSAPVerification(ctx, 'set fee exemption');
    if (!sapVerified) return;

    const userRef = db.collection('users').doc(targetUserId);
    await userRef.set({ feeExempt: exemptStatus }, { merge: true });

    await ctx.reply(`✅ User ${targetUserId} fee exemption set to ${exemptStatus}`);
    
    // Log the exemption change
    await db.collection('fee_logs').add({
      type: 'exemption',
      userId: targetUserId,
      exemptStatus: exemptStatus,
      changedBy: userId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      reason: args.slice(2).join(' ') || 'No reason provided'
    });
    
  } catch (error) {
    console.error('❌ Set Fee Exempt Error:', error);
    await ctx.reply('❌ An error occurred while setting fee exemption.');
  }
});

// Helper function to calculate fees with exemptions
async function calculateFeeWithExemptions(userId, amount) {
  try {
    // Check for fee exemption
    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    
    if (userDoc.exists && userDoc.data().feeExempt) {
      return { fee: 0, netAmount: amount, isExempt: true };
    }
    
    // Check for VIP status (50% discount)
    const isVIP = userDoc.exists && userDoc.data().vipStatus;
    const effectiveFeeRate = isVIP ? currentFee * 0.5 : currentFee;
    
    const fee = amount * effectiveFeeRate;
    return { 
      fee, 
      netAmount: amount - fee,
      isExempt: false,
      discount: isVIP ? 'VIP (50%)' : null
    };
  } catch (error) {
    console.error('Fee calculation error:', error);
    // Fallback to standard fee if error occurs
    const fee = amount * currentFee;
    return { fee, netAmount: amount - fee, isExempt: false };
  }
}

// Updated transaction saving with fee details
async function saveTransactionWithFees(userId, type, amountSOL, amountUSD, address, txId) {
  try {
    const feeDetails = await calculateFeeWithExemptions(userId, amountSOL);
    
    const txData = {
      userId: userId.toString(),
      type,
      amountSOL,
      amountUSD,
      address,
      transactionId: txId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      feeAmount: feeDetails.fee,
      netAmount: feeDetails.netAmount,
      feeRate: currentFee,
      isFeeExempt: feeDetails.isExempt,
      feeDiscount: feeDetails.discount || null
    };

    await db.collection('transactions').add(txData);
    console.log('💾 Transaction with fee details saved.');
    
    // Update user's total fees paid if not exempt
    if (!feeDetails.isExempt) {
      const userRef = db.collection('users').doc(userId.toString());
      await userRef.update({
        totalFeesPaid: admin.firestore.FieldValue.increment(feeDetails.fee),
        lastTransaction: admin.firestore.FieldValue.serverTimestamp()
      });
    }
    
    return txData;
  } catch (error) {
    console.error('❌ Transaction Save Error:', error);
    throw error;
  }
}

// Load current fee from database on startup
async function loadCurrentFee() {
  try {
    const feeRef = db.collection('system').doc('fee_settings');
    const doc = await feeRef.get();
    
    if (doc.exists && doc.data().currentFee) {
      currentFee = doc.data().currentFee;
      console.log(`Loaded current fee from DB: ${currentFee * 100}%`);
      
      // Check if we need to apply scheduled fee change
      if (doc.data().scheduledFee && doc.data().scheduledChangeTime) {
        const changeTime = doc.data().scheduledChangeTime.toDate();
        if (new Date() >= changeTime) {
          // Time to apply scheduled change
          currentFee = doc.data().scheduledFee;
          await feeRef.set({
            currentFee: currentFee,
            updatedAt: admin.firestore.FieldValue.serverTimestamp(),
            updatedBy: 'system',
            previousFee: doc.data().currentFee,
            scheduledFee: null,
            scheduledChangeTime: null
          }, { merge: true });
          console.log(`Applied scheduled fee change to ${currentFee * 100}%`);
        }
      }
    } else {
      // Initialize with default if not exists
      await feeRef.set({
        currentFee: currentFee,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        feeStructure: {
          standard: currentFee,
          vip: currentFee * 0.5,
          exempt: 0
        }
      });
      console.log(`Initialized fee settings with default: ${currentFee * 100}%`);
    }
  } catch (error) {
    console.error('Error loading fee settings:', error);
  }
}

// Schedule a future fee change
bot.command('schedulefee', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins can schedule fee changes.');
      return;
    }

    const args = ctx.message.text.split(' ').slice(1);
    if (args.length < 2) {
      await ctx.reply('❌ Usage: /schedulefee <new_fee> <YYYY-MM-DD> [HH:MM] [reason]');
      return;
    }

    const newFee = parseFloat(args[0]);
    if (isNaN(newFee) || newFee <= 0 || newFee > 1) {
      await ctx.reply('❌ Invalid fee percentage. Must be between 0 and 1.');
      return;
    }

    const dateParts = args[1].split('-');
    if (dateParts.length !== 3) {
      await ctx.reply('❌ Invalid date format. Use YYYY-MM-DD.');
      return;
    }

    let changeTime = new Date(args[1]);
    if (args[2] && args[2].includes(':')) {
      const timeParts = args[2].split(':');
      changeTime.setHours(parseInt(timeParts[0]), parseInt(timeParts[1]), 0, 0);
    } else {
      changeTime.setHours(0, 0, 0, 0);
      if (args[2] && !args[2].includes(':')) {
        // The arg after date is not a time, so it's part of the reason
        args.splice(2, 0, '00:00');
      }
    }

    if (isNaN(changeTime.getTime())) {
      await ctx.reply('❌ Invalid date/time provided.');
      return;
    }

    if (changeTime <= new Date()) {
      await ctx.reply('❌ Scheduled time must be in the future.');
      return;
    }

    const reason = args.slice(3).join(' ') || 'No reason provided';

    // Require SAP verification for admin actions
    const sapVerified = await requireSAPVerification(ctx, 'schedule fee change');
    if (!sapVerified) return;

    const feeRef = db.collection('system').doc('fee_settings');
    await feeRef.set({
      scheduledFee: newFee,
      scheduledChangeTime: changeTime,
      scheduledBy: userId,
      scheduledReason: reason
    }, { merge: true });

    await ctx.reply(
      `✅ Fee change scheduled:\n` +
      `🔄 New Fee: ${(newFee * 100).toFixed(2)}%\n` +
      `⏰ Effective: ${changeTime.toLocaleString()}\n` +
      `📝 Reason: ${reason}`
    );

    // Log the scheduled change
    await db.collection('fee_logs').add({
      type: 'scheduled',
      newFee: newFee,
      changeTime: changeTime,
      scheduledBy: userId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      reason: reason
    });
    
  } catch (error) {
    console.error('❌ Schedule Fee Error:', error);
    await ctx.reply('❌ An error occurred while scheduling fee change.');
  }
});

// Check scheduled fee changes
bot.command('checkschedule', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins can check scheduled fee changes.');
      return;
    }

    const feeRef = db.collection('system').doc('fee_settings');
    const doc = await feeRef.get();

    if (!doc.exists || !doc.data().scheduledFee) {
      await ctx.reply('ℹ️ No scheduled fee changes.');
      return;
    }

    const data = doc.data();
    const changeTime = data.scheduledChangeTime.toDate();
    const timeUntil = moment(changeTime).fromNow();

    await ctx.reply(
      `⏰ <b>Scheduled Fee Change</b>\n\n` +
      `🔄 New Fee: ${(data.scheduledFee * 100).toFixed(2)}%\n` +
      `⏳ Effective: ${changeTime.toLocaleString()} (${timeUntil})\n` +
      `👤 Scheduled by: ${data.scheduledBy}\n` +
      `📝 Reason: ${data.scheduledReason || 'Not specified'}`,
      { parse_mode: 'HTML' }
    );
    
  } catch (error) {
    console.error('❌ Check Schedule Error:', error);
    await ctx.reply('❌ An error occurred while checking scheduled changes.');
  }
});

// Cancel scheduled fee change
bot.command('cancelschedule', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins can cancel scheduled fee changes.');
      return;
    }

    const feeRef = db.collection('system').doc('fee_settings');
    const doc = await feeRef.get();

    if (!doc.exists || !doc.data().scheduledFee) {
      await ctx.reply('ℹ️ No scheduled fee changes to cancel.');
      return;
    }

    // Require SAP verification for admin actions
    const sapVerified = await requireSAPVerification(ctx, 'cancel scheduled fee change');
    if (!sapVerified) return;

    await feeRef.update({
      scheduledFee: null,
      scheduledChangeTime: null,
      scheduledBy: null,
      scheduledReason: null
    });

    await ctx.reply('✅ Scheduled fee change has been cancelled.');
    
    // Log the cancellation
    await db.collection('fee_logs').add({
      type: 'schedule_cancelled',
      cancelledBy: userId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      originalNewFee: doc.data().scheduledFee,
      originalChangeTime: doc.data().scheduledChangeTime
    });
    
  } catch (error) {
    console.error('❌ Cancel Schedule Error:', error);
    await ctx.reply('❌ An error occurred while cancelling scheduled change.');
  }
});

// Call this function when bot starts
loadCurrentFee();

// Periodically check for scheduled fee changes
setInterval(async () => {
  try {
    const feeRef = db.collection('system').doc('fee_settings');
    const doc = await feeRef.get();
    
    if (doc.exists && doc.data().scheduledFee && doc.data().scheduledChangeTime) {
      const changeTime = doc.data().scheduledChangeTime.toDate();
      if (new Date() >= changeTime) {
        // Time to apply scheduled change
        const newFee = doc.data().scheduledFee;
        currentFee = newFee;
        await feeRef.set({
          currentFee: currentFee,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
          updatedBy: 'system',
          previousFee: doc.data().currentFee,
          scheduledFee: null,
          scheduledChangeTime: null
        }, { merge: true });
        
        console.log(`Applied scheduled fee change to ${currentFee * 100}%`);
        
        // Notify admins
        const admins = ADMINS;
        for (const adminId of admins) {
          try {
            await bot.telegram.sendMessage(
              adminId,
              `⏰ <b>Scheduled Fee Change Applied</b>\n\n` +
              `The fee has been automatically changed to ${(newFee * 100).toFixed(2)}% as scheduled.`,
              { parse_mode: 'HTML' }
            );
          } catch (error) {
            console.error(`Failed to notify admin ${adminId}:`, error);
          }
        }
      }
    }
  } catch (error) {
    console.error('Error in fee schedule check:', error);
  }
}, 3600000); // Check every hour

// ----------------- Referral Logic -----------------
async function registerReferral(userId, referralCode) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists || !userDoc.data().referredBy) {
    await userRef.set({ referredBy: referralCode }, { merge: true });
    console.log(`User ${userId} referred by ${referralCode}`);
  }
}

async function updateReferralBonus(referrerCode, feePaid, transactionData, referredUserId) {
  try {
    const referredUserRef = db.collection('users').doc(referredUserId.toString());
    const referredUserDoc = await referredUserRef.get();
    if (!referredUserDoc.exists) {
      console.log('❌ Referred user not found in DB.');
      return;
    }
    const referredUserData = referredUserDoc.data();
    if (!referredUserData.joinedAt) {
      console.log('❌ Referred user does not have a joinedAt field.');
      return;
    }
    const joinedDate = referredUserData.joinedAt.toDate();
    const now = new Date();
    const yearDiff = now.getFullYear() - joinedDate.getFullYear();
    const monthDiff = (yearDiff * 12) + (now.getMonth() - joinedDate.getMonth());

    let bonusPercentage = 0.05; // default
    if (monthDiff === 0) {
      bonusPercentage = 0.25;
    } else if (monthDiff === 1) {
      bonusPercentage = 0.15;
    }

    const bonusAmount = feePaid * bonusPercentage;

    const bonusDocRef = await db.collection('referralBonuses').add({
      referrerCode,
      referredUserId,
      transactionId: transactionData.withdrawalId || transactionData.signature || 'N/A',
      feePaid,
      bonusPercentage,
      bonusAmount,
      transactionDate: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log(`✅ Referral bonus of ${bonusAmount} credited to referrer ${referrerCode} (monthDiff=${monthDiff}).`);

    let referrerId = parseInt(referrerCode.replace('ref', ''), 10);
    if (isNaN(referrerId)) {
      referrerId = parseInt(referrerCode, 10);
    }
    if (isNaN(referrerId)) {
      console.log("❌ Could not parse referrerId from code:", referrerCode);
      return;
    }
    const referrerActiveWallet = await getActiveWallet(referrerId);
    if (!referrerActiveWallet) {
      console.log("❌ Referrer has no active wallet. Skipping FARASbot transfer.");
      return;
    }
    const sig = await transferFARASbot(bonusAmount, referrerActiveWallet.publicKey);
    console.log("✅ FARASbot transferred to referrer wallet:", sig);
    await bonusDocRef.update({ farasbotTransferSignature: sig });
  } catch (error) {
    console.error('❌ updateReferralBonus Error:', error);
  }
}

async function getAllReferrals(referralCode, maxDepth = 5) {
  const queue = [{ code: referralCode, level: 0 }];
  const visited = new Set([referralCode]);

  const directRefs = [];
  const indirectRefs = [];

  while (queue.length > 0) {
    const { code: currentCode, level } = queue.shift();
    if (level >= maxDepth) continue;

    const snapshot = await db.collection('users')
      .where('referredBy', '==', currentCode)
      .get();

    for (const doc of snapshot.docs) {
      const data = doc.data();
      if (!data.referralCode) continue;

      if (!visited.has(data.referralCode)) {
        visited.add(data.referralCode);

        if (level === 0) {
          directRefs.push(data);
        } else {
          indirectRefs.push(data);
        }

        queue.push({ code: data.referralCode, level: level + 1 });
      }
    }
  }

  return { directRefs, indirectRefs };
}

async function getUserReferralStatsMultiLevel(userId, botUsername) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists) {
    return {
      code: null,
      link: null,
      directCount: 0,
      indirectCount: 0,
      totalRewards: 0,
      totalPaid: 0,
      totalUnpaid: 0,
    };
  }

  let code = userDoc.data().referralCode;
  if (!code) {
    code = `ref${userId}`;
    await userRef.set({ referralCode: code }, { merge: true });
  }
  const link = `https://t.me/${botUsername}?start=${code}`;

  const { directRefs, indirectRefs } = await getAllReferrals(code, 5);
  const directCount = directRefs.length;
  const indirectCount = indirectRefs.length;

  const snapshot = await db.collection('referralBonuses')
    .where('referrerCode', '==', code)
    .get();

  let totalRewards = 0;
  let totalPaid = 0;
  let totalUnpaid = 0;
  snapshot.forEach(doc => {
    const data = doc.data();
    const amt = data.bonusAmount || 0;
    totalRewards += amt;
    if (data.farasbotTransferSignature) {
      totalPaid += amt;
    } else {
      totalUnpaid += amt;
    }
  });

  return {
    code,
    link,
    directCount,
    indirectCount,
    totalRewards,
    totalPaid,
    totalUnpaid
  };
}

// ----------------- Helper Functions for Solana -----------------
const getSolPrice = async () => {
  try {
    const res = await axios.get('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
    return res.data.solana.usd;
  } catch (error) {
    console.error('❌ SOL Price Error:', error);
    return null;
  }
};

const isValidSolanaAddress = (address) => {
  try {
    new PublicKey(address);
    return true;
  } catch {
    return false;
  }
};

const calculateNetAmount = (amount, feeRate = 0.02) => {
  const fee = amount * feeRate;
  const netAmount = amount - fee;
  return { fee, netAmount };
};

const saveTransaction = async (userId, type, amountSOL, amountUSD, address, txId) => {
  try {
    await db.collection('transactions').add({
      userId: userId.toString(),
      type,
      amountSOL,
      amountUSD,
      address,
      transactionId: txId,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    });
    console.log('💾 Transaction saved.');
  } catch (error) {
    console.error('❌ Transaction Save Error:', error);
  }
};

const listenForIncomingTransactions = async (publicKey) => {
  if (subscriptions[publicKey]) {
    console.log(`🔔 Already subscribed for ${publicKey}`);
    return;
  }
  try {
    const subId = connection.onAccountChange(
      new PublicKey(publicKey),
      (accountInfo) => {
        console.log(`🔔 Update for ${publicKey}:`, accountInfo);
      },
      'confirmed'
    );
    subscriptions[publicKey] = subId;
    console.log(`👂 Listening on ${publicKey} (sub ID: ${subId})`);
  } catch (error) {
    console.error('❌ Subscription Error:', error);
  }
};

// ----------------- Wallet Management Functions -----------------
async function getActiveWallet(userId) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists || !userDoc.data().activeWalletId) return null;
  const walletRef = userRef.collection('wallets').doc(userDoc.data().activeWalletId);
  const walletDoc = await walletRef.get();
  return walletDoc.exists ? { id: walletDoc.id, ...walletDoc.data() } : null;
}

async function createNewWallet(userId, phone, firstName, lastName, username, email) {
  const keypair = Keypair.generate();
  const publicKey = keypair.publicKey.toString();
  const privateKeyHex = Buffer.from(keypair.secretKey).toString('hex');

  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();

  if (!userDoc.exists) {
    await userRef.set({
      phone, firstName, lastName, username, email,
      joinedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
  } else {
    if (!userDoc.data().joinedAt) {
      await userRef.set({
        joinedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    }
    await userRef.set({ phone, firstName, lastName, username, email }, { merge: true });
  }

  const walletData = {
    publicKey,
    type: 'new',
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };
  const walletRef = await userRef.collection('wallets').add(walletData);
  await userRef.update({ activeWalletId: walletRef.id });
  await listenForIncomingTransactions(publicKey);

  setLocalPrivateKey(walletRef.id, privateKeyHex);

  return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
}

async function importWalletByPrivateKey(userId, phone, firstName, lastName, username, email, privateKeyInput) {
  try {
    let secretKeyUint8;
    const trimmedKey = privateKeyInput.trim();
    if (trimmedKey.startsWith('[')) {
      secretKeyUint8 = new Uint8Array(JSON.parse(trimmedKey));
    } else if (/^[0-9a-fA-F]+$/.test(trimmedKey)) {
      secretKeyUint8 = Uint8Array.from(Buffer.from(trimmedKey, 'hex'));
    } else {
      secretKeyUint8 = decodeBase58(trimmedKey);
    }

    let keypair;
    try {
      keypair = Keypair.fromSecretKey(secretKeyUint8);
    } catch {
      try {
        keypair = Keypair.fromSeed(secretKeyUint8);
      } catch {
        throw new Error('❌ Invalid private key format.');
      }
    }

    const publicKey = keypair.publicKey.toString();

    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    if (!userDoc.exists) {
      await userRef.set({
        phone, firstName, lastName, username, email,
        joinedAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });
    } else {
      if (!userDoc.data().joinedAt) {
        await userRef.set({
          joinedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
      }
      await userRef.set({ phone, firstName, lastName, username, email }, { merge: true });
    }

    const walletData = {
      publicKey,
      type: 'import',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };
    const walletRef = await userRef.collection('wallets').add(walletData);
    await userRef.update({ activeWalletId: walletRef.id });

    await listenForIncomingTransactions(publicKey);
    setLocalPrivateKey(walletRef.id, privateKeyInput);

    return { walletId: walletRef.id, publicKey, secretKey: keypair.secretKey };
  } catch (error) {
    console.error('❌ Wallet Import Error:', error);
    throw error;
  }
}

async function recoverWalletByPhrase(userId, phone, firstName, lastName, username, email, phrase) {
  try {
    return await createNewWallet(userId, phone, firstName, lastName, username, email);
  } catch (error) {
    console.error('❌ Wallet Recovery Error:', error);
    throw error;
  }
}

async function resetWallet(userId) {
  const userRef = db.collection('users').doc(userId.toString());
  const userDoc = await userRef.get();
  if (!userDoc.exists) throw new Error('User not found');

  const userData = userDoc.data();
  const phone = userData.phone || 'Not provided';
  const firstName = userData.firstName || 'Not provided';
  const lastName = userData.lastName || 'Not provided';
  const username = userData.username || 'Not provided';
  const email = userData.email || 'Not provided';

  const newWallet = await createNewWallet(userId, phone, firstName, lastName, username, email);

  if (userData.activeWalletId) {
    const oldWalletRef = userRef.collection('wallets').doc(userData.activeWalletId);
    await oldWalletRef.update({ discarded: true, discardedAt: admin.firestore.FieldValue.serverTimestamp() });
    removeLocalPrivateKey(userData.activeWalletId);
  }
  return newWallet;
}

// ----------------- Preauthorization Functions -----------------
async function commitPreauthorization(referenceId, transactionId) {
  const commitBody = {
    schemaVersion: "1.0",
    requestId: Date.now().toString(),
    timestamp: new Date().toISOString(),
    channelName: "WEB",
    serviceName: "API_PREAUTHORIZE_COMMIT",
    serviceParams: {
      merchantUid: process.env.MERCHANT_U_ID,
      apiUserId: process.env.MERCHANT_API_USER_ID,
      apiKey: process.env.MERCHANT_API_KEY,
      referenceId,
      transactionId,
      description: "PREAUTH Commit for SOL Purchase"
    }
  };
  console.log("Commit Request Body:", commitBody);
  const commitResponse = await axios.post('https://api.waafipay.net/asm', commitBody);
  console.log("Commit Response:", commitResponse.data);
  return commitResponse.data;
}

async function cancelPreauthorization(referenceId, transactionId) {
  const cancelBody = {
    schemaVersion: "1.0",
    requestId: Date.now().toString(),
    timestamp: new Date().toISOString(),
    channelName: "WEB",
    serviceName: "API_PREAUTHORIZE_CANCEL",
    serviceParams: {
      merchantUid: process.env.MERCHANT_U_ID,
      apiUserId: process.env.MERCHANT_API_USER_ID,
      apiKey: process.env.MERCHANT_API_KEY,
      referenceId,
      transactionId,
      description: "Cancel Preauthorization for SOL Purchase"
    }
  };
  console.log("Cancel Request Body:", cancelBody);
  const cancelResponse = await axios.post('https://api.waafipay.net/asm', cancelBody);
  console.log("Cancel Response:", cancelResponse.data);
  return cancelResponse.data;
}

// ----------------- Real-Time Buy & Withdraw SOL Function -----------------
async function realTimeBuyAndWithdrawSOL(ctx, netAmount, userSolAddress) {
  try {
    if (!process.env.BOT_WALLET_SECRET) {
      throw new Error('BOT wallet not configured.');
    }

    const solPrice = await getSolPrice();
    if (!solPrice) {
      throw new Error('Unable to fetch SOL price for BOT wallet transfer.');
    }

    const solAmount = netAmount / solPrice;
    if (!(await botWalletHasSufficientSOL(solAmount))) {
      throw new Error('BOT Not send please contact help ceneter @goldmanzack has SOL balance.');
    }

    const result = await transferFromBotWallet(solAmount, userSolAddress);
    return result;
  } catch (error) {
    console.error("BOT wallet transaction error:", error.message);
    throw error;
  }
}

// ----------------- Payment Processor for Cash Buy -----------------
async function processPayment(ctx, { phoneNumber, amount, solAddress, paymentMethod }) {
  try {
    const preauthBody = {
      schemaVersion: "1.0",
      requestId: Date.now().toString(),
      timestamp: new Date().toISOString(),
      channelName: "WEB",
      serviceName: "API_PREAUTHORIZE",
      serviceParams: {
        merchantUid: process.env.MERCHANT_U_ID,
        apiUserId: process.env.MERCHANT_API_USER_ID,
        apiKey: process.env.MERCHANT_API_KEY,
        paymentMethod: "MWALLET_ACCOUNT",
        payerInfo: { accountNo: phoneNumber },
        transactionInfo: {
          referenceId: "ref" + Date.now(),
          invoiceId: "INV" + Date.now(),
          amount: amount,
          currency: "USD",
          description: "SOL Purchase Preauthorization"
        }
      }
    };
    console.log("Preauthorization Request Body:", preauthBody);

    const preauthResponse = await withTimeout(axios.post('https://api.waafipay.net/asm', preauthBody), 120000);
    console.log("Preauthorization Response:", preauthResponse.data);

    if (!(preauthResponse.data &&
          preauthResponse.data.params &&
          preauthResponse.data.params.state === "APPROVED")) {
      let errorMsg = preauthResponse.data.responseMsg || "Swap failed. We're sorry.";
      if (preauthResponse.data.errorCode === "E10205") {
        errorMsg = "Insufficient Payment USD balance. Available:";
      }
      await ctx.reply(`❌ ${errorMsg}`, { parse_mode: 'HTML' });
      ctx.session.cashBuy = null;
      return;
    }

    const referenceId = preauthResponse.data.params.referenceId;
    const transactionId = preauthResponse.data.params.transactionId;
    ctx.session.cashBuy = { referenceId, transactionId };

    // Fixed 5% fee for cash buys (0.5 USD on $10 deposit)
    const fee = amount * currentFee;
    const netAmountForConversion = amount - fee;

    let result;
    try {
      result = await withTimeout(realTimeBuyAndWithdrawSOL(ctx, netAmountForConversion, solAddress), 120000);
    } catch (error) {
      console.error("SOL transfer failed:", error.message);
      await cancelPreauthorization(referenceId, transactionId);
      await ctx.reply(`❌ ${error.message}`, { parse_mode: 'HTML' });
      ctx.session.cashBuy = null;
      return;
    }

    if (!result || !result.acquiredSol || result.acquiredSol <= 0) {
      await cancelPreauthorization(referenceId, transactionId);
      await ctx.reply(`❌ Swap failed. We're sorry.`, { parse_mode: 'HTML' });
      ctx.session.cashBuy = null;
      return;
    }

    const commitResponseData = await withTimeout(commitPreauthorization(referenceId, transactionId), 120000);
    if (commitResponseData &&
        commitResponseData.params &&
        commitResponseData.params.state === "APPROVED") {
      const userId = ctx.from.id;
      const userRef = db.collection('users').doc(userId.toString());
      const userData = (await userRef.get()).data();
      if (userData && userData.referredBy) {
        const referrerCode = userData.referredBy;
        await updateReferralBonus(referrerCode, fee, result, userId);
      }
      await ctx.reply(
        `🎉 <b>Congratulations!</b>\nYour purchase is complete.\n\n` +
        `Deposit Amount: $${amount.toFixed(2)} USD\n` +
        `Fee (5%): $${fee.toFixed(2)} USD\n` +
        `Net Amount: $${netAmountForConversion.toFixed(2)} USD\n` +
        `Acquired SOL: ${result.acquiredSol.toFixed(4)} SOL\n` +
        `Transaction ID: ${result.withdrawalId}\n` +
        `🔍 <a href="https://solscan.io/tx/${result.withdrawalId}">View on Solscan</a>`,
        { parse_mode: 'HTML' }
      );
    } else {
      await ctx.reply(`❌ Swap failed. We're sorry.`, { parse_mode: 'HTML' });
    }
    ctx.session.cashBuy = null;
  } catch (error) {
    console.error('❌ Payment Processing Error:', error);
    if (ctx.session.cashBuy && ctx.session.cashBuy.referenceId && ctx.session.cashBuy.transactionId) {
      try {
        await cancelPreauthorization(ctx.session.cashBuy.referenceId, ctx.session.cashBuy.transactionId);
      } catch (cancelError) {
        console.error("Error canceling preauthorization after error:", cancelError);
      }
    }
    await ctx.reply('❌ Payment error. Please try again later.', { parse_mode: 'HTML' });
    ctx.session.cashBuy = null;
  }
}

// ----------------- Admin Broadcast Feature -----------------
bot.command('broadcast', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins have permission. You do not have access to use this command..');
      return;
    }

    const message = ctx.message.text.replace('/broadcast', '').trim();
    if (!message) {
      await ctx.reply('❌ Please provide a message to broadcast.\nUsage: /broadcast your message here');
      return;
    }

    ctx.session.broadcastMessage = message;
    await ctx.reply(
      `⚠️ Confirm Broadcast Message:\n\n${message}\n\nThis will be sent to all users. Continue?`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('✅ Confirm Broadcast', 'confirm_broadcast'),
           Markup.button.callback('❌ Cancel', 'cancel_broadcast')]
        ])
      }
    );
  } catch (error) {
    console.error('❌ Broadcast Command Error:', error);
    await ctx.reply('❌ An error occurred while processing your broadcast request.');
  }
});

bot.action('confirm_broadcast', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.answerCbQuery('❌ Unauthorized');
      return;
    }

    if (!ctx.session.broadcastMessage) {
      await ctx.answerCbQuery('❌ No message to broadcast');
      return;
    }

    await ctx.editMessageText('⏳ Sending broadcast to all users...');
    
    const usersSnapshot = await db.collection('users').get();
    let successCount = 0;
    let failCount = 0;

    for (const doc of usersSnapshot.docs) {
      try {
        await bot.telegram.sendMessage(doc.id, `<b>UPDATE BOT ON SOLANA</b>\n\n${ctx.session.broadcastMessage}`, {
          parse_mode: 'HTML'
        });
        successCount++;
        await delay(200); // Rate limiting
      } catch (error) {
        console.error(`Failed to send to user ${doc.id}:`, error);
        failCount++;
      }
    }

    await ctx.editMessageText(
      `📢 Broadcast Complete!\n\n✅ Success: ${successCount}\n❌ Failed: ${failCount}\n\nMessage:\n${ctx.session.broadcastMessage}`,
      { parse_mode: 'HTML' }
    );
    
    delete ctx.session.broadcastMessage;
  } catch (error) {
    console.error('❌ Confirm Broadcast Error:', error);
    await ctx.reply('❌ An error occurred while sending the broadcast.');
  }
});

bot.action('cancel_broadcast', async (ctx) => {
  try {
    delete ctx.session.broadcastMessage;
    await ctx.editMessageText('❌ Broadcast cancelled.');
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Cancel Broadcast Error:', error);
    await ctx.reply('❌ An error occurred while cancelling the broadcast.');
  }
});

// ----------------- Admin Stats Command -----------------
bot.command('stats', async (ctx) => {
  try {
    const userId = ctx.from.id;
    if (!ADMINS.includes(userId)) {
      await ctx.reply('❌ Only admins have permission. You do not have access to use this command.');
      return;
    }

    await ctx.reply('⏳ Gathering statistics...');

    // Get user count
    let userCount = 0;
    try {
      const usersSnapshot = await db.collection('users').get();
      userCount = usersSnapshot.size;
    } catch (error) {
      console.error('Error getting user count:', error);
      await ctx.reply('⚠️ Could not retrieve user count');
    }

    // Get transaction count
    let txCount = 0;
    try {
      const txSnapshot = await db.collection('transactions').get();
      txCount = txSnapshot.size;
    } catch (error) {
      console.error('Error getting transaction count:', error);
      await ctx.reply('⚠️ Could not retrieve transaction count');
    }

    // Count active wallets
    async function countActiveWallets() {
      let activeWalletCount = 0;
      try {
        const usersSnapshot = await db.collection('users').get();
        for (const userDoc of usersSnapshot.docs) {
          const userData = userDoc.data();
          
          // Method 1: Use activeWalletId if exists
          if (userData.activeWalletId) {
            activeWalletCount++;
            continue;
          }

          // Method 2: Check wallets subcollection
          try {
            const walletsSnapshot = await userDoc.ref.collection('wallets').get();
            walletsSnapshot.forEach(walletDoc => {
              if (!walletDoc.data().discarded) {
                activeWalletCount++;
              }
            });
          } catch (error) {
            console.error(`Error checking wallets for user ${userDoc.id}:`, error);
          }
        }
      } catch (error) {
        console.error('Error counting wallets:', error);
      }
      return activeWalletCount;
    }

    const activeWalletCount = await countActiveWallets();

    // Get bot wallet balance
    let botBalanceSOL = 0;
    try {
      const botBalance = await connection.getBalance(botKeypair.publicKey);
      botBalanceSOL = botBalance / LAMPORTS_PER_SOL;
    } catch (error) {
      console.error('Error getting bot balance:', error);
      await ctx.reply('⚠️ Could not retrieve bot wallet balance');
    }

    // Get total fees collected
    let totalFees = 0;
    try {
      const feesSnapshot = await db.collection('transactions')
        .where('feeAmount', '>', 0)
        .get();
      
      feesSnapshot.forEach(doc => {
        totalFees += doc.data().feeAmount || 0;
      });
    } catch (error) {
      console.error('Error calculating total fees:', error);
    }

    // Format uptime
    const uptime = process.uptime();
    const days = Math.floor(uptime / 86400);
    const hours = Math.floor((uptime % 86400) / 3600);
    const minutes = Math.floor((uptime % 3600) / 60);
    const seconds = Math.floor(uptime % 60);
    const uptimeString = `${days}d ${hours}h ${minutes}m ${seconds}s`;

    await ctx.reply(
      `<b>Bot Statistics</b>\n\n` +
      `Total Users: ${userCount}\n` +
      `Active Wallets: ${activeWalletCount}\n` +
      `Total Transactions: ${txCount}\n` +
      `Total Fees Collected: ${totalFees.toFixed(4)} SOL\n` +
      `Bot Wallet Balance: ${botBalanceSOL.toFixed(4)} SOL\n` +
      `Uptime: ${uptimeString}`,
      { parse_mode: 'HTML' }
    );
  } catch (error) {
    console.error('❌ Stats Command Error:', error);
    await ctx.reply('❌ An error occurred while fetching stats. Please check logs.');
  }
});

// ----------------- Telegram Bot Commands & Actions -----------------

// /start Command
bot.command('start', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const muqdishoTime = moment().tz('Africa/Mogadishu');
    const currentHour = muqdishoTime.hour();
    const greeting = currentHour < 5
      ? '🌜 Good Night (Habeennimo wanaagsan!)'
      : currentHour < 12
      ? '🌞 Good Morning (Subaxnimo wanaagsan!)'
      : currentHour < 18
      ? '🌤️ Good Afternoon (Galabnimo wanaagsan!)'
      : '🌙 Good Evening (Fiidnimo wanaagsan!)';

    const args = ctx.message.text.split(' ');
    if (args.length > 1) {
      const referralCode = args[1].trim();
      if (referralCode) {
        await registerReferral(userId, referralCode);
      }
    }

    const userRef = db.collection('users').doc(userId.toString());
    let userDoc = await userRef.get();
    let userData = userDoc.exists ? userDoc.data() : null;

    if (!userDoc.exists || !userData.activeWalletId) {
      if (!userDoc.exists) {
        await userRef.set({ createdAt: admin.firestore.FieldValue.serverTimestamp() }, { merge: true });
        userDoc = await userRef.get();
        userData = userDoc.data();
      }

      if (!userData.referralCode) {
        await userRef.set({ referralCode: `ref${userId}` }, { merge: true });
      }

      
    };      

    if (!userData.referralCode) {
      await userRef.set({ referralCode: `ref${userId}` }, { merge: true });
    }

    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply(
        `${greeting}\n\nWelcome to <b>FarasBot on Solana</b>! 🚀\n\nYour gateway to managing your Solana wallet with speed, security, and simplicity. Whether you're new to crypto or an experienced trader, FarasBot keeps you in control.\n\nCreate and manage your wallet effortlessly, obtain SOL, and trade crypto without KYC or central restrictions. You can also purchase SOL using EVC Plus, Zaad, and Sahal, making crypto more accessible in Somalia and East Africa.\n\nFarasBot also includes advanced security features to protect your assets.\n\nStart now:\n\nChoose one of the options below to get started:\n• <b>New Account</b> – Create a new wallet.\n• <b>Import Private Key</b> – Import your existing wallet.\n• <b>Recover Phrase</b> – Recover your wallet using your recovery phrase.\n\n<em>FarasBot offers easy access to your Solana wallet with advanced security features. You can buy SOL using local methods like EVC Plus, Zaad, and Sahal, making crypto accessible in Somalia and East Africa. No KYC, no restrictions—just control at your fingertips. 🚀</em>`,
        {
          parse_mode: 'HTML',
          ...Markup.inlineKeyboard([
            [
              Markup.button.callback('🆕 New Account', 'new_account'),
              Markup.button.callback('🔑 Import Private Key', 'import_key')
            ],
            [
              Markup.button.callback('🔄 Recover Phrase', 'recover_phrase')
            ]
          ])
        }
      );
      return;
    }

    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);

    await ctx.reply(
      `🚀 Welcome Back! ${greeting}\n\nActive Wallet: I'm here to help you manage your Solana wallet.\n\nFaras on Solana – The fastest way to send, receive, and make local payments easily via Solana deposits. 🚀\n\nWallet SOLANA\n\nLet's get started! How would you like to trade today?\n\nWallet Address: ${activeWallet.publicKey}\n\nBalance: ${balanceSOL.toFixed(4)} SOL (~$${balanceUSD} USD)\n\nWhat would you like to do?`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback(' SOL Buy', 'cash_buy'),
            Markup.button.callback(' Withdrawal', 'withdrawal')
          ],
          [
            Markup.button.callback('↻ Refresh Balance', 'refresh')
          ],
          [
            Markup.button.callback('❓ Help', 'help'),
            Markup.button.callback('⚙️ Settings', 'settings')
          ],
          [
            Markup.button.callback('👥 Refer Friends', 'referral_friends')
          ]
        ])
      }
    );
  } catch (error) {
    console.error('❌ /start Error:', error);
    await ctx.reply('❌ Oops! An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('help', async (ctx) => {
  try {
    const helpMessage = `<b>Help</b>\n\n` +
      `<b>Which tokens can I trade?</b>\n` +
      `Any SPL token that is a SOL pair, on Raydium, pump.fun, Meteora, Moonshot, or Jupiter, and will integrate more platforms on a rolling basis. We pick up pairs instantly, and Jupiter will pick up non-SOL pairs within approx. 15 minutes.\n\n` +
      `<b>How can I see how much money I've made from referrals?</b>\n` +
      `Tap the referrals button or type /referrals to see your payment in $BONK!\n\n` +
      `<b>How do I create a new wallet on BONKbot?</b>\n` +
      `Tap the Wallet button or type /wallet, and you'll be able to configure your new wallets!\n\n` +
      `<b>Is BONKbot free? How much do I pay for transactions?</b>\n` +
      `BONKbot is completely free! We charge 1% on transactions, and keep the bot free so that anyone can use it.\n\n` +
      `<b>Why is my Net Profit lower than expected?</b>\n` +
      `Your Net Profit is calculated after deducting all associated costs, including Price Impact, Transfer Tax, Dex Fees, and a 1% BONKbot fee. This ensures the figure you see is what you actually receive, accounting for all transaction-related expenses.\n\n` +
      `<b>Is there a difference between @FARASbotChat and the backup bots?</b>\n` +
      `No, they are all the same bot and you can use them interchangeably. If one is slow or down, you can use the other ones. You will have access to the same wallet and positions.\n\n` +
      `<b>Further questions?</b> Join our Telegram group: <a href="https://t.me/FARASbotChat">FARASbotChat</a>`;

    await ctx.reply(helpMessage, {
      parse_mode: 'HTML',
      reply_markup: {
        inline_keyboard: [
          [
            
            { text: 'VIEW CHANNEL', url: 'https://t.me/FARASbotChat' }
          ],
          [
            { text: 'Close', callback_data: 'close_help' }
          ]
        ]
      }
    });

    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Help Action Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Close help message handler
bot.action('close_help', async (ctx) => {
  try {
    await ctx.deleteMessage();
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Error closing help message:', error);
  }
});

// Referral Friends Action - Improved Version
bot.action('referral_friends', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const botUsername = 'solana_farasbot'; // Fixed bot username

    const stats = await getUserReferralStatsMultiLevel(userId, botUsername);
    if (!stats.code) {
      return ctx.reply('❌ No referral info found. Type /start to create an account first.', { 
        parse_mode: 'HTML' 
      });
    }

    // Format the referral link properly
    const referralLink = `https://t.me/${botUsername}?start=${stats.code}`;
    
    const solPrice = await getSolPrice() || 20;
    const totalRewardsUSD = (stats.totalRewards * solPrice).toFixed(2);
    const totalPaidUSD = (stats.totalPaid * solPrice).toFixed(2);
    const totalUnpaidUSD = (stats.totalUnpaid * solPrice).toFixed(2);
    const totalRefCount = stats.directCount + stats.indirectCount;

    const messageText = 
`✨ <b>YOUR REFERRAL DASHBOARD</b> ✨
<i>Updated every 30 minutes</i>

━━━━━━━━━━━━━━━━━━━
👥 <b>YOUR NETWORK</b>
┣ Direct Referrals: <b>${stats.directCount}</b>
┗ Indirect Referrals: <b>${stats.indirectCount}</b>

💰 <b>YOUR EARNINGS</b>
┣ Total Rewards: <b>${stats.totalRewards.toFixed(4)} SOL</b> ($${totalRewardsUSD})
┣ Paid Out: <b>${stats.totalPaid.toFixed(4)} SOL</b> ($${totalPaidUSD})
┗ Pending: <b>${stats.totalUnpaid.toFixed(4)} SOL</b> ($${totalUnpaidUSD})

🔗 <b>YOUR REFERRAL LINK</b>
<code>${referralLink}</code>

🎁 <b>HOW IT WORKS</b>
When friends use your link:
┣ 1st Month: You earn <b>30%</b> of their fees
┣ 2nd Month: You earn <b>20%</b> of their fees
┗ Ongoing: You earn <b>10%</b> forever!

💡 <i>Share your link below to start earning!</i>`;

    await ctx.reply(messageText, {
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard([
        [
          Markup.button.callback('📷 QR Code', 'referral_qrcode'),
          Markup.button.callback('📤 Share', 'share_referral'),
          Markup.button.callback('❌ Close', 'close_referral_message')
        ]
      ])
    });

    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ referral_friends Error:', error);
    await ctx.reply('❌ An error occurred while fetching referral data.', { 
      parse_mode: 'HTML' 
    });
  }
});

// Action to show the QR Code - Improved Version
bot.action('referral_qrcode', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const botUsername = 'solana_farasbot'; // Fixed bot username

    const stats = await getUserReferralStatsMultiLevel(userId, botUsername);
    if (!stats.code) {
      return ctx.reply('❌ No referral info found.', { parse_mode: 'HTML' });
    }

    const referralLink = `https://t.me/${botUsername}?start=${stats.code}`;
    
    // Generate high-quality QR code
    const qrBuffer = await QRCode.toBuffer(referralLink, {
      errorCorrectionLevel: 'H',
      type: 'png',
      width: 400,
      margin: 2,
      color: {
        dark: '#000000', // Black dots
        light: '#ffffff' // White background
      }
    });

    await ctx.replyWithPhoto(
      { source: qrBuffer, filename: 'referral_qr.png' }, 
      {
        caption: `🔗 <b>Your Referral QR Code</b>\n\nScan this code to join with your referral link:\n<code>${referralLink}</code>`,
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('🔙 Back', 'referral_friends'),
          Markup.button.callback('❌ Close', 'close_referral_qr')]
        ])
      }
    );

    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ referral_qrcode Error:', error);
    await ctx.reply('❌ Failed to generate QR code. Please try again.', { 
      parse_mode: 'HTML' 
    });
  }
});

// Share referral link action
bot.action('share_referral', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const botUsername = 'solana_farasbot';
    const stats = await getUserReferralStatsMultiLevel(userId, botUsername);
    
    if (stats.code) {
      const referralLink = `https://t.me/${botUsername}?start=${stats.code}`;
      await ctx.reply(
        `📤 <b>Share Your Referral Link</b>\n\n` +
        `Copy this message to share with friends:\n\n` +
        `Join me on Solana FarasBot and get bonus rewards! 🚀\n` +
        `Use my referral link: ${referralLink}`,
        {
          parse_mode: 'HTML',
          ...Markup.inlineKeyboard([
            [Markup.button.switchToChat('💬 Share Now', 'Join FarasBot with my link!')],
            [Markup.button.callback('🔙 Back', 'referral_friends')]
          ])
        }
      );
    }
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ share_referral Error:', error);
    await ctx.answerCbQuery('❌ Failed to prepare sharing. Try again.');
  }
});

// Close handlers (unchanged)
bot.action('close_referral_message', async (ctx) => {
  try {
    await ctx.deleteMessage();
    await ctx.answerCbQuery();
  } catch (err) {
    console.error('❌ close_referral_message Error:', err);
  }
});

bot.action('close_referral_qr', async (ctx) => {
  try {
    await ctx.deleteMessage();
    await ctx.answerCbQuery();
  } catch (err) {
    console.error('❌ close_referral_qr Error:', err);
  }
});

// new_account
bot.action('new_account', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const phone = ctx.from.phone_number || 'Not provided';
    const firstName = ctx.from.first_name || 'Not provided';
    const lastName = ctx.from.last_name || 'Not provided';
    const username = ctx.from.username || 'Not provided';
    const email = ctx.from.email || 'Not provided';

    const wallet = await createNewWallet(userId, phone, firstName, lastName, username, email);
    ctx.session.secretKey = Array.from(wallet.secretKey);

    await ctx.reply(
      `✅ <b>Wallet Created Successfully!</b>\n\n<b>Address:</b> ${wallet.publicKey}\n\nYour private key is stored locally in encrypted form. To view it, use <b>Settings → Private Key</b>.`,
      { parse_mode: 'HTML' }
    );
    ctx.answerCbQuery();
    ctx.telegram.sendMessage(ctx.chat.id, '👉 Type /start to continue.', { parse_mode: 'HTML' });
  } catch (error) {
    console.error('❌ New Account Error:', error);
    await ctx.reply('❌ Error while creating a new wallet.', { parse_mode: 'HTML' });
  }
});

// import_key
bot.action('import_key', async (ctx) => {
  try {
    ctx.session.awaitingPrivateKey = true;
    await ctx.reply(
      '🔑 <b>Import Wallet</b>\n\nPlease enter your private key in Base58 format (Phantom-style) or in hex format:',
      { parse_mode: 'HTML' }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Import Key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// recover_phrase
bot.action('recover_phrase', async (ctx) => {
  try {
    ctx.session.awaitingRecoveryPhrase = true;
    await ctx.reply(
      '🔄 <b>Recover Wallet</b>\n\nEnter your recovery phrase (words separated by a space):',
      { parse_mode: 'HTML' }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Recover Phrase Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Text Handler
bot.on('text', async (ctx) => {
  try {
    // SAP Verification Flow
    if (ctx.session.awaitingSAP) {
      const sapAttempt = ctx.message.text.trim();
      const userId = ctx.from.id;
      
      // Immediately delete the password message
      try {
        await ctx.deleteMessage();
      } catch (deleteError) {
        console.log('Could not delete password message:', deleteError);
      }
      
      // Also delete previous SAP prompt messages
      for (const msgId of ctx.session.awaitingSAP.messageIds) {
        try {
          await ctx.deleteMessage(msgId);
        } catch (e) {
          console.log('Could not delete message:', e);
        }
      }
      
      try {
        const isValid = await verifyUserSAP(userId, sapAttempt);
        
        if (!isValid) {
          const remainingAttempts = SAP_MAX_ATTEMPTS - (ctx.session.awaitingSAP.attempts + 1);
          
          if (remainingAttempts <= 0) {
            await ctx.reply(
              '🔒 <b>SAP Locked</b>\n\nToo many failed attempts. Please try again later.',
              { parse_mode: 'HTML' }
            );
            delete ctx.session.awaitingSAP;
            return;
          }
          
          const newMessage = await ctx.reply(
            `❌ <b>Invalid SAP</b>\n\nAttempts remaining: ${remainingAttempts}\n\nPlease try again:`,
            { parse_mode: 'HTML' }
          );
          
          ctx.session.awaitingSAP.attempts++;
          ctx.session.awaitingSAP.messageIds = [newMessage.message_id];
          return;
        }
        
        // SAP verified - proceed with the action
        const { action, callbackData } = ctx.session.awaitingSAP;
        delete ctx.session.awaitingSAP;
        
        await handleVerifiedAction(ctx, action, callbackData);
        
      } catch (error) {
        console.error('SAP verification error:', error);
        await ctx.reply(
          `❌ ${error.message || 'SAP verification failed'}`,
          { parse_mode: 'HTML' }
        );
      }
      return;
    }

    // SAP Setting Flow
    if (ctx.session.awaitingNewSAP) {
      const newSAP = ctx.message.text.trim();
      
      try {
        // Clean up previous messages
        if (ctx.session.sapSetupMessageId) {
          await ctx.deleteMessage(ctx.session.sapSetupMessageId);
        }
        await ctx.deleteMessage();
      } catch (e) {
        console.log('Could not delete messages:', e);
      }
      
      try {
        await setUserSAP(ctx.from.id, newSAP);
        await ctx.reply(
          '✅ Secure Action Password set successfully!\n\nYou can now use it to verify sensitive actions.',
          { parse_mode: 'HTML' }
        );
      } catch (error) {
        await ctx.reply(
          `❌ ${error.message}\n\nPlease try again with a stronger password.`,
          { parse_mode: 'HTML' }
        );
        return;
      }
      
      delete ctx.session.awaitingNewSAP;
      delete ctx.session.sapSetupMessageId;
      return;
    }
    
    // SAP Change Flow - Current SAP
    if (ctx.session.awaitingCurrentSAP) {
      const currentSAP = ctx.message.text.trim();
      
      try {
        // Clean up previous messages
        if (ctx.session.sapChangeMessageId) {
          await ctx.deleteMessage(ctx.session.sapChangeMessageId);
        }
        await ctx.deleteMessage();
      } catch (e) {
        console.log('Could not delete messages:', e);
      }
      
      try {
        const isValid = await verifyUserSAP(ctx.from.id, currentSAP);
        if (!isValid) {
          throw new Error('Incorrect current SAP');
        }
        
        ctx.session.awaitingNewSAP = true;
        delete ctx.session.awaitingCurrentSAP;
        
        const message = await ctx.reply(
          '✅ Current SAP verified. Now enter your new SAP:',
          { parse_mode: 'HTML' }
        );
        
        ctx.session.sapSetupMessageId = message.message_id;
        
      } catch (error) {
        await ctx.reply(
          `❌ ${error.message || 'SAP verification failed'}`,
          { parse_mode: 'HTML' }
        );
      }
      return;
    }

    // Importing Private Key Flow
    if (ctx.session.awaitingPrivateKey) {
      const text = ctx.message.text.trim();
      const userId = ctx.from.id;
      const phone = ctx.from.phone_number || 'Not provided';
      const firstName = ctx.from.first_name || 'Not provided';
      const lastName = ctx.from.last_name || 'Not provided';
      const username = ctx.from.username || 'Not provided';
      const email = ctx.from.email || 'Not provided';

      try {
        const wallet = await importWalletByPrivateKey(userId, phone, firstName, lastName, username, email, text);
        ctx.session.secretKey = Array.from(wallet.secretKey);
        await ctx.reply(
          `✅ <b>Wallet Imported!</b>\n\n<b>Address:</b> ${wallet.publicKey}\n\nTo view your private key later, use <b>Settings → Private Key</b>.`,
          { parse_mode: 'HTML' }
        );
      } catch (error) {
        await ctx.reply('❌ Failed to import wallet. Please check your private key and try again.', { parse_mode: 'HTML' });
      }
      ctx.session.awaitingPrivateKey = false;
      return;
    }

    // Recovery Phrase Flow
    if (ctx.session.awaitingRecoveryPhrase) {
      const phrase = ctx.message.text.trim();
      const userId = ctx.from.id;
      const phone = ctx.from.phone_number || 'Not provided';
      const firstName = ctx.from.first_name || 'Not provided';
      const lastName = ctx.from.last_name || 'Not provided';
      const username = ctx.from.username || 'Not provided';
      const email = ctx.from.email || 'Not provided';

      try {
        const wallet = await recoverWalletByPhrase(userId, phone, firstName, lastName, username, email, phrase);
        ctx.session.secretKey = Array.from(wallet.secretKey);
        await ctx.reply(
          `✅ <b>Wallet Recovered!</b>\n\n<b>Address:</b> ${wallet.publicKey}\n\nTo view your private key later, use <b>Settings → Private Key</b>.`,
          { parse_mode: 'HTML' }
        );
      } catch (error) {
        await ctx.reply('❌ Failed to recover wallet. Please check your recovery phrase and try again.', { parse_mode: 'HTML' });
      }
      ctx.session.awaitingRecoveryPhrase = false;
      return;
    }

    // Sending SOL Flow - Address Input
    if (ctx.session.sendFlow && ctx.session.sendFlow.action === 'awaiting_address') {
      const toAddress = ctx.message.text.trim();
      if (!isValidSolanaAddress(toAddress)) {
        await ctx.reply('❌ Invalid SOL address. Please try again.', { parse_mode: 'HTML' });
        return;
      }
      ctx.session.sendFlow.action = 'awaiting_amount';
      ctx.session.sendFlow.toAddress = toAddress;
      await ctx.reply('💰 Enter the USD amount you want to send (minimum $1):', { parse_mode: 'HTML' });
      return;
    } 
    // Sending SOL Flow - Amount Input
    else if (ctx.session.sendFlow && ctx.session.sendFlow.action === 'awaiting_amount') {
      const amountUSD = parseFloat(ctx.message.text);
      if (isNaN(amountUSD) || amountUSD < 1) {
        await ctx.reply('❌ Please enter a valid amount (minimum $1).', { parse_mode: 'HTML' });
        return;
      }
      const solPrice = await getSolPrice();
      if (!solPrice) {
        await ctx.reply('❌ Unable to fetch SOL price. Try again later.', { parse_mode: 'HTML' });
        return;
      }
      const amountSOL = amountUSD / solPrice;
      ctx.session.sendFlow.amountSOL = amountSOL;
      ctx.session.sendFlow.amountUSD = amountUSD;
      await ctx.reply(
        `⚠️ Confirm:\nSend <b>${amountSOL.toFixed(4)} SOL</b> (≈ $${amountUSD.toFixed(2)}) to:\n<code>${ctx.session.sendFlow.toAddress}</code>`,
        {
          parse_mode: 'HTML',
          ...Markup.inlineKeyboard([
            [Markup.button.callback('✅ Confirm', 'confirm_send'),
             Markup.button.callback('❌ Cancel', 'cancel_send')]
          ])
        }
      );
      return;
    }

    // Cash Buy Flow - Phone Number Input
    if (ctx.session.cashBuy && ctx.session.cashBuy.step === 'phoneNumber') {
      const phoneNumber = ctx.message.text.trim();
      if (!/^\d{9}$/.test(phoneNumber)) {
        await ctx.reply('❌ Invalid phone number. Please enter a 9-digit number.', { parse_mode: 'HTML' });
        return;
      }
      ctx.session.cashBuy.phoneNumber = phoneNumber;
      ctx.session.cashBuy.step = 'amount';
      await ctx.reply('Enter the USD amount you wish to purchase:', { parse_mode: 'HTML' });
      return;
    } 
    // Cash Buy Flow - Amount Input
    else if (ctx.session.cashBuy && ctx.session.cashBuy.step === 'amount') {
      const amount = parseFloat(ctx.message.text);
      if (isNaN(amount) || amount < 1 || amount > 5000) {
        await ctx.reply('❌ Please enter a valid amount (minimum $2 and maximum $5000).', { parse_mode: 'HTML' });
        return;
      }
      ctx.session.cashBuy.amount = amount;
      ctx.session.cashBuy.step = 'confirm';
      const fee = amount * currentFee;
      const netAmount = amount - fee;
      const solPrice = await getSolPrice();
      const solReceived = solPrice ? (netAmount / solPrice) : 0;
      await ctx.reply(
        `*Deposit Details:*\n\n• Phone Number: ${ctx.session.cashBuy.phoneNumber}\n• Deposit Amount: $${amount.toFixed(2)}\n• Fee: $${fee.toFixed(2)}\n• Total After Fee: $${netAmount.toFixed(2)}\n• You will receive ≈ ${solReceived.toFixed(4)} SOL\n\nProceed?`,
        {
          parse_mode: 'HTML',
          reply_markup: {
            inline_keyboard: [
              [{ text: '✅ Submit', callback_data: 'submit' },
               { text: '❌ Cancel', callback_data: 'cancel' }]
            ]
          }
        }
      );
      return;
    }
  } catch (error) {
    console.error('❌ Text Handler Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

async function handleVerifiedAction(ctx, action, callbackData) {
  switch (action) {
    case 'view private key':
      await handleViewPrivateKey(ctx);
      break;
    case 'reset wallet':
      await handleResetWallet(ctx);
      break;
    case 'confirm withdrawal':
      await handleWithdrawal(ctx);
      break;
    // Add other actions as needed
    default:
      await ctx.reply(`✅ SAP verified. Continuing with ${action}...`, { parse_mode: 'HTML' });
      if (callbackData) {
        // Handle callback data if needed
      }
  }
}

async function handleViewPrivateKey(ctx) {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      throw new Error('No active wallet found');
    }
    
    const storedPrivateKey = getLocalPrivateKey(activeWallet.id);
    if (!storedPrivateKey) {
      throw new Error('Private key not available');
    }
    
    // Send private key with auto-deletion
    const keyMessage = await ctx.reply(
      `🔐 <b>Your Private Key</b>\n\n<code>${storedPrivateKey}</code>\n\n⚠️ This message will self-destruct in 30 seconds.`,
      { parse_mode: 'HTML' }
    );
    
    // Delete after 30 seconds
    setTimeout(async () => {
      try {
        await ctx.deleteMessage(keyMessage.message_id);
        await ctx.reply('🔐 Private key message has been deleted for security.', { parse_mode: 'HTML' });
      } catch (e) {
        console.error('Could not delete private key message:', e);
      }
    }, 30000);
    
  } catch (error) {
    console.error('View private key error:', error);
    await ctx.reply(`❌ ${error.message || 'Failed to retrieve private key'}`, { parse_mode: 'HTML' });
  }
}

async function handleResetWallet(ctx) {
  try {
    const userId = ctx.from.id;
    const newWallet = await resetWallet(userId);
    
    await ctx.reply(
      `✅ <b>Wallet Reset Successful!</b>\n\nA brand-new wallet has been created.\n<b>New Address:</b> ${newWallet.publicKey}\n\nYour old wallet has been discarded. Type /start to continue.`,
      { parse_mode: 'HTML' }
    );
  } catch (error) {
    console.error('Reset wallet error:', error);
    await ctx.reply(`❌ ${error.message || 'Failed to reset wallet'}`, { parse_mode: 'HTML' });
  }
}

async function handleWithdrawal(ctx) {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
      ctx.session.sendFlow = null;
      return;
    }
    
    const storedPrivateKey = getLocalPrivateKey(activeWallet.id);
    if (!storedPrivateKey) {
      await ctx.reply('❌ Private key missing. Please import your wallet using /import_key.', { parse_mode: 'HTML' });
      return;
    }

    let fromKeypair;
    if (activeWallet.type === 'import') {
      if (/^[0-9a-fA-F]+$/.test(storedPrivateKey)) {
        fromKeypair = Keypair.fromSecretKey(Buffer.from(storedPrivateKey, 'hex'));
      } else {
        fromKeypair = Keypair.fromSecretKey(decodeBase58(storedPrivateKey));
      }
    } else {
      fromKeypair = Keypair.fromSecretKey(Buffer.from(storedPrivateKey, 'hex'));
    }

    const toPublicKey = new PublicKey(ctx.session.sendFlow.toAddress);
    const balance = await connection.getBalance(fromKeypair.publicKey);
    const balanceSOL = balance / 1e9;
    if (balanceSOL < ctx.session.sendFlow.amountSOL) {
      await ctx.reply('❌ Insufficient SOL balance.', { parse_mode: 'HTML' });
      ctx.session.sendFlow = null;
      return;
    }

    const lamports = Math.round(ctx.session.sendFlow.amountSOL * 1e9);
    const transaction = new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: fromKeypair.publicKey,
        toPubkey: toPublicKey,
        lamports,
      })
    );

    const signature = await connection.sendTransaction(transaction, [fromKeypair]);

    await saveTransactionWithFees(
      userId,
      'send',
      ctx.session.sendFlow.amountSOL,
      ctx.session.sendFlow.amountUSD,
      ctx.session.sendFlow.toAddress,
      signature
    );

    await ctx.reply(
      `✅ <b>Transaction Successful!</b>\n\nYou sent <b>${ctx.session.sendFlow.amountSOL.toFixed(4)} SOL</b> (≈ $${ctx.session.sendFlow.amountUSD.toFixed(2)}) to:\n<code>${ctx.session.sendFlow.toAddress}</code>\n\n<b>TX ID:</b> ${signature}`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.url('🔍 View on Solscan', `https://solscan.io/tx/${signature}`)],
          [Markup.button.callback('❌ Close', 'close_message')]
        ])
      }
    );
    ctx.session.sendFlow = null;
  } catch (error) {
    console.error('Withdrawal error:', error);
    await ctx.reply(`❌ ${error.message || 'Withdrawal failed'}`, { parse_mode: 'HTML' });
    ctx.session.sendFlow = null;
  }
}

// Refresh Balance
bot.action('refresh', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
    }
    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);
    await ctx.reply(`🔄 Balance: <b>${balanceSOL.toFixed(4)} SOL</b> (~$${balanceUSD} USD)`, { parse_mode: 'HTML' });
  } catch (error) {
    console.error('❌ Refresh Balance Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Withdrawal
bot.action('withdrawal', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || !userDoc.data().sap) {
      await ctx.reply(
        `🔒 <b>SAP Not Set</b>\n\nYou must set a Secure Action Password before making withdrawals.\n\nPlease set your SAP first in Settings.`,
        { parse_mode: 'HTML' }
      );
      return;
    }
    
    ctx.session.sendFlow = { action: 'awaiting_address' };
    await ctx.reply('📤 Enter the recipient SOL address:', { parse_mode: 'HTML' });
  } catch (error) {
    console.error('❌ Withdrawal Action Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Confirm Send (now triggers SAP verification)
bot.action('confirm_send', async (ctx) => {
  try {
    if (!ctx.session.sendFlow || !ctx.session.sendFlow.toAddress) {
      await ctx.reply('❌ Transaction not initiated properly.', { parse_mode: 'HTML' });
      return;
    }
    
    await requireSAPVerification(ctx, 'confirm withdrawal');
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Confirm Send Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Cancel Send
bot.action('cancel_send', async (ctx) => {
  try {
    await ctx.reply('❌ Transaction canceled.', { parse_mode: 'HTML' });
    ctx.session.sendFlow = null;
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Cancel Send Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Cash Buy Flow
bot.action('cash_buy', (ctx) => {
  ctx.session.cashBuy = {};
  ctx.reply('💲 <b>Purchase SOL</b>\n\nChoose a payment method:', {
    reply_markup: {
      inline_keyboard: [
        [{ text: 'EVC Plus', callback_data: 'evcplus' }, { text: 'Zaad', callback_data: 'zaad' }],
        [{ text: 'Sahal', callback_data: 'sahal' }],
        [{ text: '🔙 Back to Main Menu', callback_data: 'back_to_main' }]
      ]
    },
    parse_mode: 'HTML'
  });
});

bot.action(['evcplus', 'zaad', 'sahal'], (ctx) => {
  if (!ctx.session.cashBuy) {
    ctx.session.cashBuy = {}; // initialize if it doesn't exist
  }

  ctx.session.cashBuy.paymentMethod = ctx.match[0];
  ctx.session.cashBuy.step = 'phoneNumber';

  ctx.reply(
    `You selected <b>${ctx.match[0].toUpperCase()}</b>.\n\nPlease enter your 9-digit phone number:`,
    { parse_mode: 'HTML' }
  );
});


bot.action('submit', async (ctx) => {
  try {
    if (!ctx.session.cashBuy) {
      await ctx.reply('❌ No purchase session found.', { parse_mode: 'HTML' });
      return;
    }
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      await ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
      return;
    }
    ctx.session.cashBuy.solAddress = activeWallet.publicKey;
    ctx.session.cashBuy.step = 'processing';

    await ctx.reply(`Using your SOL address:\n<code>${activeWallet.publicKey}</code>\n\nProcessing payment... ⏳`, { parse_mode: 'HTML' });

    await processPayment(ctx, {
      phoneNumber: ctx.session.cashBuy.phoneNumber,
      amount: ctx.session.cashBuy.amount,
      solAddress: activeWallet.publicKey,
      paymentMethod: ctx.session.cashBuy.paymentMethod
    });
  } catch (error) {
    console.error('❌ Cash Buy Submit Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('cancel', (ctx) => {
  if (!ctx.session.cashBuy) {
    ctx.reply('❌ No purchase session found.', { parse_mode: 'HTML' });
    return;
  }
  ctx.reply('❌ Transaction cancelled. Returning to main menu...', {
    reply_markup: {
      inline_keyboard: [
        [{ text: '💰 Buy SOL', callback_data: 'cash_buy' },
         { text: '💸 Sell SOL', callback_data: 'sell' }]
      ]
    },
    parse_mode: 'HTML'
  });
  ctx.session.cashBuy = null;
});

// Settings
bot.action('settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ <b>Settings Menu</b>\n\nGENERAL SETTINGS
Language: Shows the current language. Tap to switch between available languages.
Minimum Position Value: Minimum position value to show in portfolio. Will hide tokens below this threshold. Tap to edit.
`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback('🔐 Private Key', 'show_private_key'),
            Markup.button.callback('🗄️ Manage Wallet', 'manage_wallet')
          ],
          [
            Markup.button.callback('🔒 Set SAP', 'set_sap'),
            Markup.button.callback('🔄 Change SAP', 'change_sap')
          ],
          [
            Markup.button.callback('🚨 Reset Wallet', 'reset_wallet_prompt'),
            Markup.button.callback('🔙 Back to Main Menu', 'back_to_main')
          ]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Settings Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Show Private Key (with SAP verification)
bot.action('show_private_key', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || !userDoc.data().sap) {
      await ctx.reply(
        `🔒 <b>SAP Not Set</b>\n\nYou must set a Secure Action Password before viewing your private key.\n\nPlease set your SAP first in Settings.`,
        { parse_mode: 'HTML' }
      );
      return;
    }

    await ctx.editMessageText(
      `⚠️ <b>Final Warning!</b>\n\nAre you sure you want to reveal your Private Key?\n\nOnce revealed, make sure to keep it safe and do not share it with anyone.`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('❌ Cancel', 'back_to_settings'),
           Markup.button.callback('✅ Proceed', 'confirm_show_private_key')]
        ])
      }
    );
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ show_private_key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('confirm_show_private_key', async (ctx) => {
  try {
    await requireSAPVerification(ctx, 'view private key');
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ confirm_show_private_key Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Set SAP
bot.action('set_sap', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    
    if (userDoc.exists && userDoc.data().sap) {
      await ctx.reply('❌ SAP already set. Use "Change SAP" to update it.', { parse_mode: 'HTML' });
      return;
    }
    
    ctx.session.awaitingNewSAP = true;
const message = await ctx.reply(
  `🔒 <b>Set Secure Action Password</b>\n\n` +
  `Please create a strong password that:\n` +
  `• Is at least ${SAP_MIN_LENGTH} characters long\n` +
  `• Contains at least one number\n` +
  `• Contains at least one special character (!@#$%^&*(),.?":{}|&lt;&gt;)\n\n` + // Halkan waxaa loo beddelay `<>` si Telegram u aqbalo
  `This password will be required for sensitive actions such as:\n` +
  `• Withdrawing funds from your wallet\n` +
  `• Viewing your private key to safeguard your account\n\n` +
  `Make sure this password is secure and unique. It is crucial for your account's security.\n\n` +
  `⚠️ <b>Important Warning:</b> If you forget your Secure Action Password, you will not be able to perform sensitive actions, such as withdrawing your funds or viewing your private key. This password is vital for protecting your account and assets.\n\n` +
  `<b>Make sure to store it safely!</b> If you lose it, we cannot help you recover it, and your funds will be inaccessible.\n\n` +
  `<b>Please enter your password:</b>`,
  { parse_mode: 'HTML' }
);

        
    
    // Store message ID for cleanup
    ctx.session.sapSetupMessageId = message.message_id;
    
  } catch (error) {
    console.error('❌ Set SAP Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Change SAP
bot.action('change_sap', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || !userDoc.data().sap) {
      await ctx.reply(
        '❌ No SAP set. Use "Set SAP" to create one first.',
        { parse_mode: 'HTML' }
      );
      return;
    }
    
    ctx.session.awaitingCurrentSAP = true;
    const message = await ctx.reply(
      '🔒 <b>Change Secure Action Password</b>\n\nFirst, enter your current SAP:',
      { parse_mode: 'HTML' }
    );
    
    // Store message ID for cleanup
    ctx.session.sapChangeMessageId = message.message_id;
    
  } catch (error) {
    console.error('❌ Change SAP Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Manage Wallet
bot.action('manage_wallet', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const snapshot = await db.collection('users').doc(userId.toString()).collection('wallets').get();
    const wallets = [];
    snapshot.forEach(doc => wallets.push({ id: doc.id, ...doc.data() }));
    if (wallets.length === 0) {
      await ctx.reply('❌ No wallets found. Please create or import a wallet first.', { parse_mode: 'HTML' });
      return;
    }
    const keyboard = wallets.map(w => [Markup.button.callback(w.publicKey, `select_wallet_${w.id}`)]);
    keyboard.push([Markup.button.callback('🔙 Back to Settings', 'back_to_settings')]);
    await ctx.editMessageText('<b>Select Wallet:</b>\nChoose the wallet you wish to use:', {
      parse_mode: 'HTML',
      ...Markup.inlineKeyboard(keyboard)
    });
  } catch (error) {
    console.error('❌ Manage Wallet Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action(/select_wallet_(.+)/, async (ctx) => {
  try {
    const walletId = ctx.match[1];
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    await userRef.update({ activeWalletId: walletId });
    ctx.session.secretKey = null;
    await ctx.reply('✅ Active wallet updated. (If needed, import its private key via /import_key).', { parse_mode: 'HTML' });
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Select Wallet Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('back_to_settings', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚙️ <b>Settings Menu</b>\n\nChoose an option:`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback('🔐 Private Key', 'show_private_key'),
            Markup.button.callback('🗄️ Manage Wallet', 'manage_wallet')
          ],
          [
            Markup.button.callback('🔒 Set SAP', 'set_sap'),
            Markup.button.callback('🔄 Change SAP', 'change_sap')
          ],
          [
            Markup.button.callback('🚨 Reset Wallet', 'reset_wallet_prompt'),
            Markup.button.callback('🔙 Back to Main Menu', 'back_to_main')
          ]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Back to Settings Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Reset Wallet Prompt
bot.action('reset_wallet_prompt', async (ctx) => {
  try {
    await ctx.editMessageText(
      `⚠️ <b>RESET WALLET</b>\n\nAre you sure you want to reset your FARASbot Wallet?\n\n<b>WARNING!</b> This action will create a brand-new wallet and discard your old one.\n\nEnsure you have exported your private key/seed phrase to avoid permanent loss.\n\n<b>This action is irreversible!</b>`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('❌ Cancel', 'back_to_settings'),
           Markup.button.callback('✅ Confirm', 'reset_wallet_confirm')]
        ]),
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_prompt Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Reset Wallet Confirm
bot.action('reset_wallet_confirm', async (ctx) => {
  try {
    await ctx.editMessageText(
      `CONFIRM: Are you <b>absolutely sure</b> you want to reset your FARASbot Wallet?\n\nOnce done, you <b>cannot</b> recover your old wallet.\n\nLast chance to cancel!`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [Markup.button.callback('❌ Cancel', 'back_to_settings'),
           Markup.button.callback('✅ FINAL CONFIRM', 'reset_wallet_final')]
        ]),
      }
    );
    ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_confirm Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Reset Wallet Final (with SAP verification)
bot.action('reset_wallet_final', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const userRef = db.collection('users').doc(userId.toString());
    const userDoc = await userRef.get();
    
    if (!userDoc.exists || !userDoc.data().sap) {
      await ctx.reply(
        `🔒 <b>SAP Not Set</b>\n\nYou must set a Secure Action Password before resetting your wallet.\n\nPlease set your SAP first in Settings.`,
        { parse_mode: 'HTML' }
      );
      return;
    }
    
    await requireSAPVerification(ctx, 'reset wallet');
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ reset_wallet_final Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// Back to Main Menu
bot.action('back_to_main', async (ctx) => {
  try {
    const userId = ctx.from.id;
    const activeWallet = await getActiveWallet(userId);
    if (!activeWallet) {
      return ctx.reply('❌ No active wallet found. Use /start to create or import a wallet.', { parse_mode: 'HTML' });
    }
    const balance = await connection.getBalance(new PublicKey(activeWallet.publicKey));
    const balanceSOL = balance / 1e9;
    const solPrice = await getSolPrice();
    const balanceUSD = (balanceSOL * solPrice).toFixed(2);
    ctx.session.sendFlow = null;
    ctx.session.cashBuy = null;
    const muqdishoTime = moment().tz('Africa/Mogadishu');
    const currentHour = muqdishoTime.hour();
    const greeting = currentHour < 5
      ? '🌜 Good Night (Habeennimo wanaagsan!)'
      : currentHour < 12
      ? '🌞 Good Morning (Subaxnimo wanaagsan!)'
      : currentHour < 18
      ? '🌤️ Good Afternoon (Galabnimo wanaagsan!)'
      : '🌙 Good Evening (Fiidnimo wanaagsan!)';
    await ctx.editMessageText(
      `🚀 *Welcome Back! ${greeting}\n\n👋Active Wallet: I'm here to help you manage your Solana wallet.\n\nFaras on Solana – The fastest way to send, receive, and make local payments easily via Solana deposits. 🚀\n\n Wallet SOLANA\n\nLet's get started! How would you like to trade today?\n\nWallet Address: ${activeWallet.publicKey}\n\nBalance: ${balanceSOL.toFixed(4)} SOL (~$${balanceUSD} USD)\n\nWhat would you like to do?`,
      {
        parse_mode: 'HTML',
        ...Markup.inlineKeyboard([
          [
            Markup.button.callback('SOL Buy', 'cash_buy'),
            Markup.button.callback('Withdrawal', 'withdrawal')
          ],
          [
            Markup.button.callback('↻ Refresh Balance', 'refresh')
          ],
          [
            Markup.button.callback('❓ Help', 'help'),
            Markup.button.callback('⚙️ Settings', 'settings')
          ],
          [
            Markup.button.callback('👥 Refer Friends', 'referral_friends')
          ]
        ]),
      }
    );
  } catch (error) {
    console.error('❌ Back to Main Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

bot.action('close_message', async (ctx) => {
  try {
    await ctx.reply('🎉 <b>Transaction Completed Successfully!</b>', { parse_mode: 'HTML' });
    await ctx.answerCbQuery();
  } catch (error) {
    console.error('❌ Close Message Error:', error);
    await ctx.reply('❌ An error occurred. Please try again later.', { parse_mode: 'HTML' });
  }
});

// ----------------- Error Handling -----------------
bot.catch((err, ctx) => {
  console.error(`❌ Error for ${ctx.updateType}:`, err);
  ctx.reply('❌ An unexpected error occurred. Please try again later.');
});

// ----------------- Launch the Bot -----------------
bot.launch()
  .then(() => console.log('🚀 Bot is live!'))
  .catch((error) => {
    console.error('❌ Bot Launch Error:', error);
  });

// Enable graceful stop
process.once('SIGINT', () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));