const bcrypt = require('bcrypt');

function login(req,res){
    if(req.session.loggedin!=true){
        res.render('login/index');
    }else{
        res.redirect('/');
    }    
}

function auth(req,res){
    const data = req.body;
    req.getConnection((err,conn)=>{
        conn.query('select * from empleado where empUsuario = ?',[data.empUsuario],(err,userdata)=>{
            if(userdata.length > 0){
                userdata.forEach(element => {
                    bcrypt.compare(data.empContraseña,element.empContraseña,(err,isMatch)=>{
                    
                        if(!isMatch){
                            res.render('login/index',{error:'¡Contraseña incorrecta!'});
                        }else{
                            req.session.loggedin = true;
                            req.session.empNombre = element.empNombre;

                            res.redirect('/');
                        }
                    });                    
                });
            }else{
                res.render('login/index',{error:'¡Usuario no existe!'});
            }});
        });
}

function register(req,res){
    if(req.session.loggedin!=true){
        res.render('login/register');
    }else{
        res.redirect('/');
    } 
}

function storeUser(req,res){
    const data = req.body;

    req.getConnection((err,conn)=>{
        conn.query('select * from empleado where empUsuario = ?',[data.empUsuario],(err,userdata)=>{
            if(userdata.length > 0){
                res.render('login/register',{error:'¡Usuario ya registrado!'});
            }else{
                bcrypt.hash(data.empContraseña,12).then(hash =>{
                    data.empContraseña = hash;        
                    req.getConnection((err,conn) =>{
                        console.log(data);
                        conn.query('Insert into empleado set?',[data],(err,rows)=>{
                            req.session.loggedin = true;
                            req.session.empNombre = data.empNombre;
                            res.redirect('/');
                        })
                    });
                });
            }
        })
    })    
}

function logout(req,res){
    if(req.session.loggedin==true){
        req.session.destroy();
        req
    }
        res.redirect('/login');
    
}

module.exports={
    login,
    register,
    storeUser,
    auth,
    logout,
}