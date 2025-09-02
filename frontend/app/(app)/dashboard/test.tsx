"use client"

export default function TestDashboard() {
  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto">
      <div className="bg-red-500 p-4 text-white rounded">
        <h1 className="text-3xl font-bold">TEST DASHBOARD</h1>
        <p>If you can see this, the dashboard routing is working!</p>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div className="bg-blue-500 p-4 text-white rounded">Card 1</div>
        <div className="bg-green-500 p-4 text-white rounded">Card 2</div>
        <div className="bg-purple-500 p-4 text-white rounded">Card 3</div>
      </div>
    </div>
  )
}
