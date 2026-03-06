import { useState,useEffect } from "react"
import api from "../api/client"

export default function WorkerStatus(){

 const [workers,setWorkers]=useState([])

 useEffect(()=>{

  load()

 },[])

 const load=async()=>{

  const res=await api.get("/admin/workers")

  setWorkers(res.data)
 }

 return(

  <div>

   <h3>Workers</h3>

   {workers.map(w=>(
    <div key={w.id}>
     {w.hostname} - {w.status}
    </div>
   ))}

  </div>

 )
}