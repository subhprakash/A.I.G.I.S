import { useState } from "react"
import api from "../api/client"

export default function Upload(){

 const [file,setFile]=useState(null)

 const upload=async()=>{

  const form=new FormData()

  form.append("file",file)

  const res=await api.post("/scan/upload",form)

  alert(`Job created: ${res.data.job_id}`)
 }

 return(

  <div>

   <h2>Upload Scan Target</h2>

   <input type="file"
    onChange={e=>setFile(e.target.files[0])}
   />

   <button onClick={upload}>Start Scan</button>

  </div>

 )
}