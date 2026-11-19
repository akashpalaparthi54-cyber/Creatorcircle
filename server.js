require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'creatorcircle.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, channel_url TEXT NOT NULL, niche TEXT NOT NULL,
 language TEXT NOT NULL, subscribers TEXT NOT NULL, goals TEXT DEFAULT '',
 bio TEXT DEFAULT '', role TEXT NOT NULL DEFAULT 'member', created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, txn_ref TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', submitted_at TEXT NOT NULL, expires_at TEXT,
 reviewed_at TEXT, reviewed_by INTEGER, UNIQUE(user_id, txn_ref),
 FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS ideas (
 id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, niche TEXT NOT NULL,
 language TEXT NOT NULL, hook TEXT NOT NULL, outline TEXT NOT NULL, script TEXT NOT NULL,
 is_premium INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS collabs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, from_user INTEGER NOT NULL, to_user INTEGER NOT NULL,
 message TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL,
 FOREIGN KEY(from_user) REFERENCES users(id), FOREIGN KEY(to_user) REFERENCES users(id)
);
`);
const now = () => new Date().toISOString();
const seedIdeas = [
 ['3 mistakes beginners make in [NICHE]','All','both','“If you are starting [NICHE], avoid these three mistakes.”','1. Name the common mistake. 2. Show why it hurts. 3. Give a simple fix. 4. Invite viewers to share their experience.','HOOK: If you are new to [NICHE], this can save you time.\\n\\nBODY: Mistake one is [example]. Instead, try [solution]. Mistake two is [example]. A better approach is [solution]. Mistake three is [example].\\n\\nCTA: Which one have you faced? Tell me below.'],
 ['A 30-second tutorial your audience can save','Education','both','“Save this quick tutorial for the next time you need to [TASK].”','Show the result first, explain 3 steps, recap the benefit.','HOOK: Want to [RESULT] without [PAIN]?\\n\\nSTEP 1: [Action].\\nSTEP 2: [Action].\\nSTEP 3: [Action].\\n\\nCTA: Save this and share it with someone learning [TOPIC].'],
 ['తెలుగులో 3 beginner tips','All','te','“మీరు [TOPIC] కొత్తగా నేర్చుకుంటున్నారా? ఈ 3 విషయాలు గుర్తుంచుకోండి.”','1. సమస్యను చెప్పండి. 2. మూడు సులభమైన సూచనలు ఇవ్వండి. 3. చిన్న ఉదాహరణ చూపండి.','HOOK: మీరు [TOPIC] నేర్చుకుంటున్నట్లయితే ఈ వీడియో మీకోసమే.\\n\\nTIP 1: [సూచన].\\nTIP 2: [సూచన].\\nTIP 3: [సూచన].\\n\\nCTA: మీకు ఏ tip ఉపయోగపడింది? కామెంట్‌లో చెప్పండి.'],
 ['Turn one long video into five Shorts','Education','both','“You do not need five new topics. Find five moments inside one useful video.”','Extract: a strong opinion, a how-to step, a mistake, a myth, and a result.','HOOK: One long video can become five Shorts.\\n\\n1. Cut one useful tip. 2. Cut one common mistake. 3. Cut one surprising fact. 4. Cut one before/after. 5. Cut one audience question.\\n\\nCTA: Try this with your next upload.']
];
if (db.prepare('SELECT COUNT(*) n FROM ideas').get().n === 0) {
 const ins = db.prepare('INSERT INTO ideas(title,niche,language,hook,outline,script,is_premium,created_at) VALUES(?,?,?,?,?,?,1,?)');
 seedIdeas.forEach(x => ins.run(...x, now()));
}
function ensureAdmin() {
 const email = (process.env.ADMIN_EMAIL || 'admin@creatorcircle.in').toLowerCase();
 const pass = process.env.ADMIN_PASSWORD || 'ChangeThisAdminPassword123!';
 const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email);
 if (!existing) {
  const hash = bcrypt.hashSync(pass, 12);
  db.prepare(`INSERT INTO users(name,email,password_hash,channel_url,niche,language,subscribers,role,created_at)
  VALUES(?,?,?,?,?,?,?,?,?)`).run('CreatorCircle Admin', email, hash, 'https://youtube.com', 'All', 'both', 'Any', 'admin', now());
 }
}
ensureAdmin();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: false }));
app.use(session({
 store: new SQLiteStore({ db: 'sessions.db', dir: DATA_DIR }),
 secret: process.env.SESSION_SECRET || 'dev-only-change-this-session-secret',
 resave: false, saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 }
}));
app.use(express.static(path.join(__dirname, 'public')));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 30, standardHeaders: 'draft-7', legacyHeaders: false });
const clean = v => String(v || '').trim();
const userPublic = u => ({ id:u.id, name:u.name, email:u.email, channel_url:u.channel_url, niche:u.niche, language:u.language, subscribers:u.subscribers, goals:u.goals, bio:u.bio, role:u.role });
function requireAuth(req,res,next){ if(!req.session.userId) return res.status(401).json({error:'Please log in first.'}); next(); }
function currentUser(req){ return db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId); }
function activeMembership(id){ const m=db.prepare("SELECT * FROM memberships WHERE user_id=? AND status='approved' ORDER BY expires_at DESC LIMIT 1").get(id); return !!m && new Date(m.expires_at)>new Date(); }
function requireMember(req,res,next){ if(!activeMembership(req.session.userId)) return res.status(403).json({error:'An active ₹19/month membership is required.'}); next(); }
function requireAdmin(req,res,next){ const u=currentUser(req); if(!u || u.role!=='admin') return res.status(403).json({error:'Admin access only.'}); next(); }
app.get('/api/config',(req,res)=>res.json({brand:'CreatorCircle',price:19,currency:'INR',upiId:process.env.UPI_ID||'',upiPayee:process.env.UPI_PAYEE||'CreatorCircle'}));
app.post('/api/register',authLimiter,async(req,res)=>{
 const name=clean(req.body.name), email=clean(req.body.email).toLowerCase(), password=String(req.body.password||'');
 const channel=clean(req.body.channel_url), niche=clean(req.body.niche), language=clean(req.body.language), subscribers=clean(req.body.subscribers);
 if(!name||!email||password.length<8||!/^https?:\/\/(www\.)?(youtube\.com|youtu\.be)\//i.test(channel)||!niche||!language||!subscribers) return res.status(400).json({error:'Complete all fields. Password must be at least 8 characters and channel must be a YouTube URL.'});
 try{
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare(`INSERT INTO users(name,email,password_hash,channel_url,niche,language,subscribers,goals,bio,created_at)
  VALUES(?,?,?,?,?,?,?,?,?,?)`).run(name,email,hash,channel,niche,language,subscribers,clean(req.body.goals),clean(req.body.bio),now());
  req.session.userId=info.lastInsertRowid;
  res.json({user:userPublic(currentUser(req)),member:false});
 }catch(e){res.status(409).json({error:'That email is already registered.'});}
});
app.post('/api/login',authLimiter,async(req,res)=>{
 const u=db.prepare('SELECT * FROM users WHERE email=?').get(clean(req.body.email).toLowerCase());
 if(!u||!(await bcrypt.compare(String(req.body.password||''),u.password_hash))) return res.status(401).json({error:'Email or password is incorrect.'});
 req.session.userId=u.id; res.json({user:userPublic(u),member:activeMembership(u.id)});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',requireAuth,(req,res)=>{
 const u=currentUser(req), m=db.prepare("SELECT status,submitted_at,expires_at FROM memberships WHERE user_id=? ORDER BY id DESC LIMIT 1").get(u.id);
 res.json({user:userPublic(u),member:activeMembership(u.id),membership:m||null});
});
app.put('/api/profile',requireAuth,(req,res)=>{
 const name=clean(req.body.name), niche=clean(req.body.niche), language=clean(req.body.language), subscribers=clean(req.body.subscribers), goals=clean(req.body.goals), bio=clean(req.body.bio);
 if(!name||!niche||!language||!subscribers) return res.status(400).json({error:'Please complete required profile fields.'});
 db.prepare('UPDATE users SET name=?,niche=?,language=?,subscribers=?,goals=?,bio=? WHERE id=?').run(name,niche,language,subscribers,goals,bio,req.session.userId);
 res.json({user:userPublic(currentUser(req))});
});
app.get('/api/creators',requireAuth,requireMember,(req,res)=>{
 const me=currentUser(req);
 const others=db.prepare('SELECT id,name,channel_url,niche,language,subscribers,goals,bio FROM users WHERE id<>? AND role="member" ORDER BY created_at DESC LIMIT 100').all(me.id);
 const ranked=others.map(u=>{
  let score=0; if(u.niche===me.niche||u.niche==='All')score+=4;
  if(u.language===me.language||u.language==='both'||me.language==='both')score+=3;
  if(u.subscribers===me.subscribers)score+=2;
  if(me.goals&&u.goals&&me.goals.toLowerCase().split(/[ ,]+/).some(w=>w.length>3&&u.goals.toLowerCase().includes(w)))score+=1;
  return {...u,match_score:score};
 }).sort((a,b)=>b.match_score-a.match_score).slice(0,40);
 res.json(ranked);
});
app.get('/api/ideas',requireAuth,requireMember,(req,res)=>{
 const niche=clean(req.query.niche);
 const rows=niche?db.prepare("SELECT * FROM ideas WHERE niche IN (?, 'All') ORDER BY id DESC").all(niche):db.prepare('SELECT * FROM ideas ORDER BY id DESC').all();
 res.json(rows);
});
app.post('/api/collabs',requireAuth,requireMember,(req,res)=>{
 const to=Number(req.body.to_user), message=clean(req.body.message);
 if(!to||to===req.session.userId||message.length<10||message.length>500)return res.status(400).json({error:'Write a collaboration message between 10 and 500 characters.'});
 const target=db.prepare('SELECT id FROM users WHERE id=? AND role="member"').get(to);
 if(!target)return res.status(404).json({error:'Creator not found.'});
 db.prepare('INSERT INTO collabs(from_user,to_user,message,created_at) VALUES(?,?,?,?)').run(req.session.userId,to,message,now());
 res.json({ok:true});
});
app.get('/api/collabs',requireAuth,requireMember,(req,res)=>{
 const rows=db.prepare(`SELECT c.*, a.name from_name, b.name to_name FROM collabs c JOIN users a ON a.id=c.from_user JOIN users b ON b.id=c.to_user WHERE c.from_user=? OR c.to_user=? ORDER BY c.id DESC`).all(req.session.userId,req.session.userId);
 res.json(rows);
});
app.post('/api/collabs/:id/respond',requireAuth,requireMember,(req,res)=>{
 const status=req.body.status==='accepted'?'accepted':'declined';
 const info=db.prepare("UPDATE collabs SET status=? WHERE id=? AND to_user=? AND status='pending'").run(status,Number(req.params.id),req.session.userId);
 if(!info.changes)return res.status(404).json({error:'Request not found.'}); res.json({ok:true});
});
app.post('/api/membership/request',requireAuth,(req,res)=>{
 const ref=clean(req.body.txn_ref);
 if(ref.length<6||ref.length>80)return res.status(400).json({error:'Enter a valid UPI transaction/reference number.'});
 if(activeMembership(req.session.userId))return res.status(400).json({error:'Your membership is already active.'});
 try{
  db.prepare('INSERT INTO memberships(user_id,txn_ref,submitted_at) VALUES(?,?,?)').run(req.session.userId,ref,now());
  res.json({ok:true,message:'Payment reference submitted. Admin will verify it and update your access.'});
 }catch(e){res.status(409).json({error:'This reference has already been submitted.'});}
});
app.get('/api/admin/overview',requireAuth,requireAdmin,(req,res)=>{
 res.json({
  stats:{users:db.prepare('SELECT COUNT(*) n FROM users WHERE role="member"').get().n,active:db.prepare("SELECT COUNT(DISTINCT user_id) n FROM memberships WHERE status='approved' AND expires_at>?").get(now()).n,pending:db.prepare("SELECT COUNT(*) n FROM memberships WHERE status='pending'").get().n,ideas:db.prepare('SELECT COUNT(*) n FROM ideas').get().n},
  requests:db.prepare(`SELECT m.*,u.name,u.email FROM memberships m JOIN users u ON u.id=m.user_id ORDER BY CASE status WHEN 'pending' THEN 0 ELSE 1 END, m.id DESC LIMIT 100`).all(),
  ideas:db.prepare('SELECT * FROM ideas ORDER BY id DESC').all()
 });
});
app.post('/api/admin/membership/:id',requireAuth,requireAdmin,(req,res)=>{
 const id=Number(req.params.id), action=req.body.action;
 const m=db.prepare("SELECT * FROM memberships WHERE id=? AND status='pending'").get(id);
 if(!m)return res.status(404).json({error:'Pending request not found.'});
 if(action==='approve'){
  const expires=new Date(Date.now()+30*24*60*60*1000).toISOString();
  db.prepare("UPDATE memberships SET status='approved',expires_at=?,reviewed_at=?,reviewed_by=? WHERE id=?").run(expires,now(),req.session.userId,id);
 }else if(action==='reject'){
  db.prepare("UPDATE memberships SET status='rejected',reviewed_at=?,reviewed_by=? WHERE id=?").run(now(),req.session.userId,id);
 }else return res.status(400).json({error:'Unknown action.'});
 res.json({ok:true});
});
app.post('/api/admin/ideas',requireAuth,requireAdmin,(req,res)=>{
 const fields=['title','niche','language','hook','outline','script'].map(k=>clean(req.body[k]));
 if(fields.some(x=>!x))return res.status(400).json({error:'Complete all idea fields.'});
 db.prepare('INSERT INTO ideas(title,niche,language,hook,outline,script,is_premium,created_at) VALUES(?,?,?,?,?,?,1,?)').run(...fields,now());
 res.json({ok:true});
});
app.delete('/api/admin/ideas/:id',requireAuth,requireAdmin,(req,res)=>{
 db.prepare('DELETE FROM ideas WHERE id=?').run(Number(req.params.id));res.json({ok:true});
});
app.get('/api/health',(req,res)=>res.json({ok:true,service:'CreatorCircle'}));
app.use('/api',(err,req,res,next)=>{console.error(err);res.status(500).json({error:'Something went wrong. Please try again.'});});
app.listen(PORT,()=>console.log(`CreatorCircle running on ${PORT}`));
