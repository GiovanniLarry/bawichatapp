// Test script for room reporting functionality
const fetch = require('node-fetch');

async function testRoomReporting() {
    console.log('Testing room reporting functionality...');
    
    // Test 1: Check if the API endpoint exists
    try {
        const response = await fetch('http://localhost:3000/api/rooms/test-room-id/report', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                reason: 'inappropriate',
                description: 'Test report'
            })
        });
        
        console.log('API endpoint test - Status:', response.status);
        const data = await response.json();
        console.log('API endpoint test - Response:', data);
    } catch (error) {
        console.error('API endpoint test failed:', error.message);
    }
    
    // Test 2: Check admin reported rooms endpoint
    try {
        const response = await fetch('http://localhost:3000/api/admin/reported-rooms', {
            headers: { 'Authorization': 'Bearer test-token' }
        });
        
        console.log('Admin endpoint test - Status:', response.status);
        const data = await response.json();
        console.log('Admin endpoint test - Response:', data);
    } catch (error) {
        console.error('Admin endpoint test failed:', error.message);
    }
}

// Run the test
testRoomReporting().catch(console.error); 