const express=require('express');
const session=require('express-session');
const bcrypt=require('bcryptjs');
const Database=require('better-sqlite3');
const path=require('path');

const app=express();
const db=new Database('titancrest.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'investor',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS investments(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 plan TEXT NOT NULL,
 amount_gbp REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'Demo',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
 secret:process.env.SESSION_SECRET||'CHANGE_THIS_SECRET_BEFORE_DEPLOYING',
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:86400000}
}));
app.use(express.static(path.join(__dirname,'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

function auth(req,res,next){if(!req.session.userId)return res.status(401).json({error:'Not signed in'});next();}
function user(req){return db.prepare('SELECT id,name,email,role,created_at FROM users WHERE id=?').get(req.session.userId);}

app.post('/api/register',(req,res)=>{
 const {name,email,password}=req.body;
 if(!name||!email||!password||password.length<8)return res.status(400).json({error:'Name, email and an 8+ character password are required.'});
 try{
  const hash=bcrypt.hashSync(password,12);
  const info=db.prepare('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)').run(name,email.toLowerCase(),hash);
  req.session.userId=info.lastInsertRowid;
  res.json({ok:true,user:user(req)});
 }catch(e){res.status(400).json({error:'An account with that email may already exist.'});}
});
app.post('/api/login',(req,res)=>{
 const row=db.prepare('SELECT * FROM users WHERE email=?').get((req.body.email||'').toLowerCase());
 if(!row||!bcrypt.compareSync(req.body.password||'',row.password_hash))return res.status(401).json({error:'Invalid email or password.'});
 req.session.userId=row.id;res.json({ok:true,user:user(req)});
});
app.post('/api/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',auth,(req,res)=>{
 const u=user(req);
 const investments=db.prepare('SELECT plan,amount_gbp,status,created_at FROM investments WHERE user_id=? ORDER BY id DESC').all(u.id);
 res.json({user:u,investments});
});
app.post('/api/demo-investment',auth,(req,res)=>{
 const allowed={'Foundation':800,'Momentum':2500,'Legacy':10000};
 const amount=allowed[req.body.plan];
 if(!amount)return res.status(400).json({error:'Invalid demo plan.'});
 db.prepare('INSERT INTO investments(user_id,plan,amount_gbp,status) VALUES(?,?,?,?)').run(req.session.userId,req.body.plan,amount,'Demo');
 res.json({ok:true});
});
app.listen(process.env.PORT||3000,()=>console.log('Titan Crest portal running on http://localhost:3000'));
