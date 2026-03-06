import { BrowserRouter, Routes, Route } from "react-router-dom"

import Login from "./pages/Login"
import Upload from "./pages/Upload"
import Dashboard from "./pages/Dashboard"
import Results from "./pages/Results"
import Reports from "./pages/Reports"
import History from "./pages/History"

import Navbar from "./components/Navbar"

export default function App(){

 return(
  <BrowserRouter>

   <Navbar/>

   <Routes>

    <Route path="/" element={<Login/>} />

    <Route path="/upload" element={<Upload/>} />

    <Route path="/dashboard" element={<Dashboard/>} />

    <Route path="/results/:jobId" element={<Results/>} />

    <Route path="/reports" element={<Reports/>} />

    <Route path="/history" element={<History/>} />

   </Routes>

  </BrowserRouter>
 )
}