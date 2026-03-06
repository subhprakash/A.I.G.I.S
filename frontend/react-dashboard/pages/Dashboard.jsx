import { useEffect,useState } from "react"
import api from "../api/client"

export default function Dashboard(){

 const [jobs,setJobs]=useState([])

 useEffect(()=>{

  loadJobs()

 },[])

 const loadJobs=async()=>{

  const res=await api.get("/scan/jobs")

  setJobs(res.data)
 }

 return(

  <div>

   <h2>Scan Jobs</h2>

   <table>

    <thead>
     <tr>
      <th>ID</th>
      <th>Input</th>
      <th>Status</th>
     </tr>
    </thead>

    <tbody>

     {jobs.map(j=>(
      <tr key={j.id}>
       <td>{j.id}</td>
       <td>{j.input_name}</td>
       <td>{j.status}</td>
      </tr>
     ))}

    </tbody>

   </table>

  </div>

 )
}