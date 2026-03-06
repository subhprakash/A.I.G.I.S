import { useEffect,useState } from "react"
import { useParams } from "react-router-dom"
import api from "../api/client"

export default function Results(){

 const {jobId}=useParams()

 const [data,setData]=useState(null)

 useEffect(()=>{

  load()

 },[])

 const load=async()=>{

  const res=await api.get(`/scan/results/${jobId}`)

  setData(res.data)
 }

 if(!data) return <div>Loading...</div>

 return(

  <div>

   <h2>Results</h2>

   <pre>{JSON.stringify(data,null,2)}</pre>

  </div>

 )
}