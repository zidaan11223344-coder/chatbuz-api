
import bcrypt from "bcryptjs";

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(data, status=200, extra={}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, "access-control-allow-origin":"*", "access-control-allow-headers":"Authorization, Content-Type", "access-control-allow-methods":"GET,POST,PATCH,DELETE,OPTIONS", ...extra }
  });
}
function uuid(){ return crypto.randomUUID(); }
function b64u(bytes){ let s=""; const a=new Uint8Array(bytes); for(const x of a)s+=String.fromCharCode(x); return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""); }
function unb64u(s){ s=s.replace(/-/g,"+").replace(/_/g,"/"); while(s.length%4)s+="="; const bin=atob(s); return Uint8Array.from(bin,c=>c.charCodeAt(0)); }
const enc=new TextEncoder();
async function signJwt(payload, secret){
  const head=b64u(enc.encode(JSON.stringify({alg:"HS256",typ:"JWT"})));
  const body=b64u(enc.encode(JSON.stringify({...payload,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+60*60*24*30})));
  const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const sig=await crypto.subtle.sign("HMAC",key,enc.encode(head+"."+body));
  return head+"."+body+"."+b64u(sig);
}
async function verifyJwt(token, secret){
  try{
    const [h,p,s]=token.split(".");
    if(!h||!p||!s) return null;
    const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["verify"]);
    const ok=await crypto.subtle.verify("HMAC",key,unb64u(s),enc.encode(h+"."+p));
    if(!ok)return null;
    const payload=JSON.parse(new TextDecoder().decode(unb64u(p)));
    if(payload.exp && payload.exp < Math.floor(Date.now()/1000))return null;
    return payload;
  }catch{return null;}
}
function publicUser(u){
  return {id:u.id,username:u.username,displayName:u.display_name,avatarUrl:u.avatar_url||null,bio:u.bio||null,
    role:u.role||"user",permissions:parsePerms(u.admin_permissions),points:Number(u.points||0),createdAt:u.created_at};
}
function parsePerms(v){ try{return typeof v==="string"?JSON.parse(v||"{}"):(v||{});}catch{return{};} }
function norm(v){return String(v||"").trim().toLowerCase();}
function validUsername(v){return /^[a-zA-Z0-9_]{3,32}$/.test(v);}
function validUuid(v){return /^[0-9a-f-]{36}$/i.test(v);}
async function body(req){try{return await req.json()}catch{return null}}

async function auth(req, env){
  const h=req.headers.get("authorization")||"";
  if(!h.startsWith("Bearer ")) return {error:json({ok:false,error:"unauthorized",message:"يلزم تسجيل الدخول."},401)};
  const p=await verifyJwt(h.slice(7),env.JWT_SECRET);
  if(!p?.sub)return {error:json({ok:false,error:"invalid_token",message:"رمز الدخول غير صالح أو منتهي."},401)};
  const u=await env.DB.prepare("SELECT id,username,display_name,avatar_url,bio,points,role,admin_permissions,created_at FROM users WHERE id=?").bind(p.sub).first();
  if(!u)return {error:json({ok:false,error:"unauthorized",message:"جلسة المستخدم غير صالحة."},401)};
  return {user:u};
}
function admin(u){return ["owner","admin","assistant"].includes(u.role)}
function perm(u,p){return u.role==="owner"||u.role==="admin"||parsePerms(u.admin_permissions)[p]===true}

async function handle(req,env){
  const url=new URL(req.url), path=url.pathname, method=req.method;
  if(method==="OPTIONS")return json({},204);
  if(path==="/health/live")return json({ok:true,service:"chat-buzz-api",status:"alive"});
  if(path==="/health"){
    try{await env.DB.prepare("SELECT 1").first();return json({ok:true,service:"chat-buzz-api",version:"2.0.0-cloudflare",database:"ready",timestamp:new Date().toISOString()})}
    catch{return json({ok:false,service:"chat-buzz-api",database:"error",timestamp:new Date().toISOString()},503)}
  }
  if(path==="/api/v1")return json({ok:true,name:"Chat Buzz API",version:"v1",endpoints:{health:"/health",auth:"/api/v1/auth/register, /api/v1/auth/login, /api/v1/me",rooms:"/api/v1/rooms",messages:"/api/v1/rooms/:roomId/messages",gifts:"/api/v1/gifts, /api/v1/gifts/send"}});

  if(path==="/api/v1/auth/register"&&method==="POST"){
    const b=await body(req); if(!b||!validUsername(b.username)||String(b.displayName||"").trim().length<2||String(b.displayName).length>80||String(b.password||"").length<6||String(b.password).length>128)
      return json({ok:false,error:"validation_error",message:"تحقق من البيانات المرسلة."},400);
    const username=norm(b.username), hash=await bcrypt.hash(b.password,12), id=uuid();
    try{
      await env.DB.prepare("INSERT INTO users(id,username,display_name,password_hash) VALUES(?,?,?,?)").bind(id,username,String(b.displayName).trim(),hash).run();
      const u=await env.DB.prepare("SELECT id,username,display_name,avatar_url,bio,points,role,admin_permissions,created_at FROM users WHERE id=?").bind(id).first();
      return json({ok:true,user:publicUser(u),token:await signJwt({sub:id,username,role:"user"},env.JWT_SECRET)},201);
    }catch(e){if(String(e.message).includes("UNIQUE"))return json({ok:false,error:"username_taken",message:"اسم المستخدم مستخدم مسبقاً."},409);throw e}
  }
  if(path==="/api/v1/auth/login"&&method==="POST"){
    const b=await body(req), username=norm(b?.username);
    if(!username||!b?.password)return json({ok:false,error:"validation_error",message:"تحقق من البيانات المرسلة."},400);
    const u=await env.DB.prepare("SELECT id,username,display_name,avatar_url,bio,points,password_hash,role,admin_permissions,created_at FROM users WHERE username=?").bind(username).first();
    if(!u||!(await bcrypt.compare(String(b.password),u.password_hash)))return json({ok:false,error:"invalid_credentials",message:"اسم المستخدم أو كلمة المرور غير صحيحة."},401);
    return json({ok:true,user:publicUser(u),token:await signJwt({sub:u.id,username:u.username,role:u.role||"user"},env.JWT_SECRET)});
  }
  if(path==="/api/v1/me"&&method==="GET"){
    const a=await auth(req,env);if(a.error)return a.error;return json({ok:true,user:publicUser(a.user)});
  }
  if(path==="/api/v1/users/search"&&method==="GET"){
    const a=await auth(req,env);if(a.error)return a.error;const q=String(url.searchParams.get("q")||"").trim();
    if(q.length<2)return json({ok:true,users:[]});
    const rows=await env.DB.prepare("SELECT id,username,display_name,avatar_url,bio,points,role,admin_permissions,created_at FROM users WHERE lower(username) LIKE ? OR lower(display_name) LIKE ? ORDER BY display_name LIMIT 20").bind("%"+q.toLowerCase()+"%","%"+q.toLowerCase()+"%").all();
    return json({ok:true,users:rows.results.map(publicUser)});
  }
  if(path==="/api/v1/rooms"&&method==="GET"){
    const cat=url.searchParams.get("category"); const sql=cat?
      `SELECT r.*,u.username owner_username,u.display_name owner_display_name,(SELECT COUNT(*) FROM room_members rm WHERE rm.room_id=r.id) member_count FROM rooms r JOIN users u ON u.id=r.owner_id WHERE r.is_live=1 AND r.category=? ORDER BY r.created_at DESC LIMIT 100`:
      `SELECT r.*,u.username owner_username,u.display_name owner_display_name,(SELECT COUNT(*) FROM room_members rm WHERE rm.room_id=r.id) member_count FROM rooms r JOIN users u ON u.id=r.owner_id WHERE r.is_live=1 ORDER BY r.created_at DESC LIMIT 100`;
    const q=cat?env.DB.prepare(sql).bind(cat):env.DB.prepare(sql), rows=await q.all();
    return json({ok:true,rooms:rows.results.map(r=>({id:r.id,name:r.name,description:r.description,category:r.category,coverUrl:r.cover_url,isLive:!!r.is_live,maxMembers:r.max_members,memberCount:Number(r.member_count),owner:{id:r.owner_id,username:r.owner_username,displayName:r.owner_display_name},createdAt:r.created_at}))});
  }
  if(path==="/api/v1/rooms"&&method==="POST"){
    const a=await auth(req,env);if(a.error)return a.error;const b=await body(req);
    if(!b||String(b.name||"").trim().length<2||String(b.name).length>80)return json({ok:false,error:"validation_error",message:"تحقق من البيانات المرسلة."},400);
    const id=uuid(), max=Math.min(Math.max(Number(b.maxMembers||100),2),10000);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO rooms(id,owner_id,name,description,category,cover_url,max_members) VALUES(?,?,?,?,?,?,?)").bind(id,a.user.id,String(b.name).trim(),b.description||null,String(b.category||"عام"),b.coverUrl||null,max),
      env.DB.prepare("INSERT INTO room_members(room_id,user_id,role) VALUES(?,?,?)").bind(id,a.user.id,"owner")
    ]);
    const r=await env.DB.prepare("SELECT * FROM rooms WHERE id=?").bind(id).first();
    return json({ok:true,room:{...r,coverUrl:r.cover_url,isLive:!!r.is_live,maxMembers:r.max_members,memberCount:1}},201);
  }
  const rm=path.match(/^\/api\/v1\/rooms\/([^/]+)(?:\/(join|leave|messages))?$/);
  if(rm){
    const roomId=rm[1], action=rm[2];
    if(action==="messages"){
      const a=await auth(req,env);if(a.error)return a.error;
      const m=await env.DB.prepare("SELECT role FROM room_members WHERE room_id=? AND user_id=?").bind(roomId,a.user.id).first();
      if(!m)return json({ok:false,error:"not_a_member",message:"انضم إلى الغرفة أولاً."},403);
      if(method==="GET"){
        const limit=Math.min(Math.max(Number(url.searchParams.get("limit")||50),1),100);
        const rows=await env.DB.prepare("SELECT m.*,u.username,u.display_name,u.avatar_url FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.room_id=? ORDER BY m.created_at DESC LIMIT ?").bind(roomId,limit).all();
        return json({ok:true,messages:rows.results.reverse().map(m=>({id:m.id,body:m.body,createdAt:m.created_at,sender:{id:m.sender_id,username:m.username,displayName:m.display_name,avatarUrl:m.avatar_url}}))});
      }
      if(method==="POST"){const b=await body(req);if(!b||!String(b.body||"").trim()||String(b.body).length>2000)return json({ok:false,error:"validation_error",message:"تحقق من البيانات المرسلة."},400);
        const id=uuid();await env.DB.prepare("INSERT INTO messages(id,room_id,sender_id,body) VALUES(?,?,?,?)").bind(id,roomId,a.user.id,String(b.body).trim()).run();
        const m=await env.DB.prepare("SELECT * FROM messages WHERE id=?").bind(id).first();
        return json({ok:true,message:{id:m.id,body:m.body,createdAt:m.created_at,sender:publicUser(a.user)}},201);
      }
    }
    if(action==="join"&&method==="POST"){const a=await auth(req,env);if(a.error)return a.error;const r=await env.DB.prepare("SELECT id,max_members,is_live FROM rooms WHERE id=?").bind(roomId).first();if(!r)return json({ok:false,error:"room_not_found",message:"الغرفة غير موجودة."},404);if(!r.is_live)return json({ok:false,error:"room_closed",message:"الغرفة مغلقة حالياً."},409);
      const mem=await env.DB.prepare("SELECT role FROM room_members WHERE room_id=? AND user_id=?").bind(roomId,a.user.id).first();const c=await env.DB.prepare("SELECT COUNT(*) count FROM room_members WHERE room_id=?").bind(roomId).first();
      if(!mem&&Number(c.count)>=r.max_members)return json({ok:false,error:"room_full",message:"الغرفة ممتلئة."},409);
      await env.DB.prepare("INSERT INTO room_members(room_id,user_id,role) VALUES(?,?,?) ON CONFLICT(room_id,user_id) DO UPDATE SET joined_at=CURRENT_TIMESTAMP").bind(roomId,a.user.id,mem?.role||"listener").run();
      return json({ok:true,roomId,role:mem?.role||"listener"});
    }
    if(action==="leave"&&method==="POST"){const a=await auth(req,env);if(a.error)return a.error;const r=await env.DB.prepare("SELECT owner_id FROM rooms WHERE id=?").bind(roomId).first();if(!r)return json({ok:false,error:"room_not_found",message:"الغرفة غير موجودة."},404);if(r.owner_id===a.user.id)return json({ok:false,error:"owner_cannot_leave",message:"مالك الغرفة لا يغادرها؛ أغلقها أو سلّم الملكية أولاً."},409);await env.DB.prepare("DELETE FROM room_members WHERE room_id=? AND user_id=?").bind(roomId,a.user.id).run();return json({ok:true,roomId});}
    if(!action&&method==="GET"){const r=await env.DB.prepare("SELECT r.*,u.username owner_username,u.display_name owner_display_name FROM rooms r JOIN users u ON u.id=r.owner_id WHERE r.id=?").bind(roomId).first();if(!r)return json({ok:false,error:"room_not_found",message:"الغرفة غير موجودة."},404);const ms=await env.DB.prepare("SELECT u.id,u.username,u.display_name,u.avatar_url,rm.role,rm.joined_at FROM room_members rm JOIN users u ON u.id=rm.user_id WHERE rm.room_id=? ORDER BY rm.joined_at LIMIT 200").bind(roomId).all();return json({ok:true,room:{id:r.id,name:r.name,description:r.description,category:r.category,coverUrl:r.cover_url,isLive:!!r.is_live,maxMembers:r.max_members,owner:{id:r.owner_id,username:r.owner_username,displayName:r.owner_display_name},members:ms.results.map(m=>({id:m.id,username:m.username,displayName:m.display_name,avatarUrl:m.avatar_url,role:m.role,joinedAt:m.joined_at})),createdAt:r.created_at}});}
  }
  if(path==="/api/v1/gifts"&&method==="GET"){const rows=await env.DB.prepare("SELECT id,code,name,emoji,image_url,price FROM gifts WHERE active=1 ORDER BY price").all();return json({ok:true,gifts:rows.results.map(g=>({id:g.id,code:g.code,name:g.name,emoji:g.emoji,imageUrl:g.image_url,price:Number(g.price)}))});}
  if(path==="/api/v1/gifts/send"&&method==="POST"){
    const a=await auth(req,env);if(a.error)return a.error;const b=await body(req);if(!b||!validUuid(b.giftId)||!validUuid(b.recipientId)||Number(b.quantity||1)<1||Number(b.quantity||1)>100)return json({ok:false,error:"validation_error",message:"تحقق من البيانات المرسلة."},400);
    const qty=Number(b.quantity||1), g=await env.DB.prepare("SELECT id,code,name,emoji,image_url,price FROM gifts WHERE id=? AND active=1").bind(b.giftId).first();if(!g)return json({ok:false,error:"gift_not_found",message:"الهدية غير موجودة."},404);
    const rec=await env.DB.prepare("SELECT id,username,display_name,avatar_url,bio,points,created_at,role,admin_permissions FROM users WHERE id=?").bind(b.recipientId).first();if(!rec)return json({ok:false,error:"recipient_not_found",message:"المستقبل غير موجود."},404);
    if(b.roomId){const c=await env.DB.prepare("SELECT COUNT(*) count FROM room_members WHERE room_id=? AND user_id IN (?,?)").bind(b.roomId,a.user.id,b.recipientId).first();if(Number(c.count)<2)return json({ok:false,error:"room_membership_required",message:"يجب أن يكون المرسل والمستقبل داخل الغرفة."},403)}
    const total=Number(g.price)*qty, sender=await env.DB.prepare("SELECT points FROM users WHERE id=?").bind(a.user.id).first();if(!sender||Number(sender.points)<total)return json({ok:false,error:"insufficient_points",message:"رصيد النقاط غير كافٍ.",balance:Number(sender?.points||0),required:total},409);
    const tx=uuid(), batch=await env.DB.batch([
      env.DB.prepare("UPDATE users SET points=points-?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND points>=?").bind(total,a.user.id,total),
      env.DB.prepare("UPDATE users SET points=points+?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(total,b.recipientId),
      env.DB.prepare("INSERT INTO gift_transactions(id,gift_id,sender_id,recipient_id,room_id,quantity,total_points) VALUES(?,?,?,?,?,?,?)").bind(tx,g.id,a.user.id,b.recipientId,b.roomId||null,qty,total)
    ]);
    if(batch[0].meta.changes!==1)return json({ok:false,error:"insufficient_points",message:"رصيد النقاط غير كافٍ."},409);
    return json({ok:true,transaction:{id:tx,gift:{id:g.id,code:g.code,name:g.name,emoji:g.emoji,imageUrl:g.image_url,price:Number(g.price)},sender:publicUser(a.user),recipient:publicUser(rec),roomId:b.roomId||null,quantity:qty,totalPoints:total,createdAt:new Date().toISOString(),remainingPoints:Number(sender.points)-total}},201);
  }
  if(path==="/api/v1/gifts/history"&&method==="GET"){
    const a=await auth(req,env);if(a.error)return a.error;const rows=await env.DB.prepare(`SELECT gt.id,gt.quantity,gt.total_points,gt.room_id,gt.created_at,g.code,g.name,g.emoji,g.image_url,su.id sender_id,su.username sender_username,su.display_name sender_display_name,ru.id recipient_id,ru.username recipient_username,ru.display_name recipient_display_name FROM gift_transactions gt JOIN gifts g ON g.id=gt.gift_id JOIN users su ON su.id=gt.sender_id JOIN users ru ON ru.id=gt.recipient_id WHERE gt.sender_id=? OR gt.recipient_id=? ORDER BY gt.created_at DESC LIMIT 100`).bind(a.user.id,a.user.id).all();
    return json({ok:true,transactions:rows.results.map(x=>({id:x.id,quantity:x.quantity,totalPoints:Number(x.total_points),roomId:x.room_id,gift:{code:x.code,name:x.name,emoji:x.emoji,imageUrl:x.image_url},sender:{id:x.sender_id,username:x.sender_username,displayName:x.sender_display_name},recipient:{id:x.recipient_id,username:x.recipient_username,displayName:x.recipient_display_name},createdAt:x.created_at}))});
  }

  // Admin API retained from the Railway backend.
  if(path.startsWith("/api/v1/admin/")){
    const a=await auth(req,env);if(a.error)return a.error;if(!admin(a.user))return json({ok:false,error:"admin_required",message:"هذه العملية متاحة للإدارة فقط."},403);
    if(path==="/api/v1/admin/summary"&&method==="GET"){const u=await env.DB.prepare("SELECT COUNT(*) count FROM users").first(),r=await env.DB.prepare("SELECT COUNT(*) count,SUM(CASE WHEN is_live=1 THEN 1 ELSE 0 END) live_count FROM rooms").first(),g=await env.DB.prepare("SELECT COUNT(*) count FROM gifts WHERE active=1").first();return json({ok:true,summary:{users:Number(u.count),rooms:Number(r.count),liveRooms:Number(r.live_count||0),activeGifts:Number(g.count),role:a.user.role,permissions:parsePerms(a.user.admin_permissions)}})}
    if(path==="/api/v1/admin/users"&&method==="GET"){if(!perm(a.user,"manage_users"))return json({ok:false,error:"permission_required",message:"لا تملك صلاحية تنفيذ هذه العملية."},403);const x=await env.DB.prepare("SELECT id,username,display_name,avatar_url,bio,points,role,admin_permissions,created_at FROM users ORDER BY created_at DESC LIMIT 200").all();return json({ok:true,users:x.results.map(publicUser)})}
    if(path==="/api/v1/admin/users"&&method==="POST"){if(!perm(a.user,"manage_users"))return json({ok:false,error:"permission_required",message:"لا تملك صلاحية تنفيذ هذه العملية."},403);const b=await body(req);if(!b||!validUsername(b.username)||String(b.displayName||"").length<2||String(b.password||"").length<6)return json({ok:false,error:"validation_error",message:"تحقق من البيانات المرسلة."},400);const id=uuid(),hash=await bcrypt.hash(b.password,12);try{await env.DB.prepare("INSERT INTO users(id,username,display_name,password_hash) VALUES(?,?,?,?)").bind(id,norm(b.username),b.displayName,hash).run();const u=await env.DB.prepare("SELECT id,username,display_name,avatar_url,bio,points,role,admin_permissions,created_at FROM users WHERE id=?").bind(id).first();return json({ok:true,user:publicUser(u)},201)}catch(e){if(String(e.message).includes("UNIQUE"))return json({ok:false,error:"username_taken",message:"اسم المستخدم مستخدم مسبقاً."},409);throw e}}
    if(path.match(/^\/api\/v1\/admin\/users\/[^/]+\/role$/)&&method==="PATCH"){if(a.user.role!=="owner")return json({ok:false,error:"owner_required",message:"هذه العملية متاحة لمالك التطبيق فقط."},403);const id=path.split("/")[5],b=await body(req);if(!["user","admin","assistant"].includes(b?.role))return json({ok:false,error:"validation_error",message:"الدور غير صالح."},400);if(id===a.user.id)return json({ok:false,error:"cannot_change_owner",message:"لا يمكن تغيير دور مالك التطبيق."},409);const x=await env.DB.prepare("UPDATE users SET role=?,admin_permissions=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND role<>'owner' RETURNING id,username,display_name,avatar_url,bio,points,role,admin_permissions,created_at").bind(b.role,JSON.stringify(b.role==="assistant"?b.permissions||{}:{}),id).first();if(!x)return json({ok:false,error:"user_not_found",message:"المستخدم غير موجود أو هو مالك التطبيق."},404);return json({ok:true,user:publicUser(x)})}
    const um=path.match(/^\/api\/v1\/admin\/users\/([^/]+)$/);if(um&&method==="DELETE"){if(!perm(a.user,"manage_users"))return json({ok:false,error:"permission_required",message:"لا تملك صلاحية تنفيذ هذه العملية."},403);const id=um[1],t=await env.DB.prepare("SELECT id,role FROM users WHERE id=?").bind(id).first();if(!t)return json({ok:false,error:"user_not_found",message:"المستخدم غير موجود."},404);if(t.role==="owner")return json({ok:false,error:"owner_protected",message:"لا يمكن حذف مالك التطبيق."},403);if(t.role!=="user"&&a.user.role!=="owner")return json({ok:false,error:"owner_required",message:"حذف حسابات الإدارة متاح للمالك فقط."},403);await env.DB.prepare("DELETE FROM users WHERE id=?").bind(id).run();return json({ok:true,userId:id})}
    const rs=path.match(/^\/api\/v1\/admin\/rooms\/([^/]+)\/status$/);if(rs&&method==="PATCH"){if(!perm(a.user,"manage_rooms"))return json({ok:false,error:"permission_required",message:"لا تملك صلاحية تنفيذ هذه العملية."},403);const b=await body(req);if(typeof b?.isLive!=="boolean")return json({ok:false,error:"validation_error",message:"isLive غير صالح."},400);const x=await env.DB.prepare("UPDATE rooms SET is_live=?,updated_at=CURRENT_TIMESTAMP WHERE id=? RETURNING id,is_live").bind(b.isLive?1:0,rs[1]).first();if(!x)return json({ok:false,error:"room_not_found",message:"الغرفة غير موجودة."},404);return json({ok:true,room:{id:x.id,isLive:!!x.is_live}})}
    const rd=path.match(/^\/api\/v1\/admin\/rooms\/([^/]+)$/);if(rd&&method==="DELETE"){if(!perm(a.user,"manage_rooms"))return json({ok:false,error:"permission_required",message:"لا تملك صلاحية تنفيذ هذه العملية."},403);const x=await env.DB.prepare("DELETE FROM rooms WHERE id=? RETURNING id").bind(rd[1]).first();if(!x)return json({ok:false,error:"room_not_found",message:"الغرفة غير موجودة."},404);return json({ok:true,roomId:rd[1]})}
  }
  return json({ok:false,error:"not_found",message:"المسار غير موجود."},404);
}
export default { async fetch(req,env){ try{return await handle(req,env)}catch(e){console.error(e);return json({ok:false,error:"internal_error",message:"حدث خطأ داخلي في الخادم."},500)} } };
