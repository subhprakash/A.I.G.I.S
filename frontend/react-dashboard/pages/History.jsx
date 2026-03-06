import { useEffect,useState } from "react"
import api from "../api/client"

export default function History(){

 const [jobs,setJobs]=useState([])

 useEffect(()=>{

  load()

 },[])

 const load=async()=>{

  const res=await api.get("/scan/jobs")

  setJobs(res.data)
 }

 return(

  <div>

   <h2>Scan History</h2>

   {jobs.map(j=>(
    <div key={j.id}>
     Job {j.id} - {j.status}
    </div>
   ))}

  </div>

 )
}