import { useState,useEffect } from "react"
import api from "../api/client"

export default function Reports(){

 const [reports,setReports]=useState([])

 useEffect(()=>{

  load()

 },[])

 const load=async()=>{

  const res=await api.get("/scan/reports")

  setReports(res.data)
 }

 return(

  <div>

   <h2>Reports</h2>

   {reports.map(r=>(
    <div key={r.id}>

     Job {r.job_id}

     <a href={`http://localhost:8000/api/reports/${r.job_id}/download`}>
      Download
     </a>

    </div>
   ))}

  </div>

 )
}