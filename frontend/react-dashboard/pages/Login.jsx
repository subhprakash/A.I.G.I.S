import { useState } from "react"
import api from "../api/client"

export default function Login(){

 const [username,setUsername]=useState("")
 const [password,setPassword]=useState("")

 const login=async()=>{

  const res=await api.post("/auth/login",{username,password})

  localStorage.setItem("token",res.data.access_token)

  window.location="/dashboard"
 }

 return(

  <div>

   <h2>AIGIS Login</h2>

   <input
    placeholder="Username"
    onChange={e=>setUsername(e.target.value)}
   />

   <input
    type="password"
    placeholder="Password"
    onChange={e=>setPassword(e.target.value)}
   />

   <button onClick={login}>Login</button>

  </div>

 )
}