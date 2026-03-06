export default function JobTable({jobs}){

 return(

  <table>

   <thead>
    <tr>
     <th>ID</th>
     <th>Status</th>
    </tr>
   </thead>

   <tbody>

    {jobs.map(j=>(
     <tr key={j.id}>
      <td>{j.id}</td>
      <td>{j.status}</td>
     </tr>
    ))}

   </tbody>

  </table>

 )
}