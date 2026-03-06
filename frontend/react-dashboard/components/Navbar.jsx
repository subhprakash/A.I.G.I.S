import { Link } from "react-router-dom"

export default function Navbar(){

 return(

  <nav>

   <Link to="/dashboard">Dashboard</Link>

   <Link to="/upload">Upload</Link>

   <Link to="/reports">Reports</Link>

   <Link to="/history">History</Link>

  </nav>

 )
}