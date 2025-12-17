# Bawi Admin Dashboard

A comprehensive administrative dashboard for managing the Bawi chat application.

## Features

### 🔐 Authentication
- Secure admin login with username/password
- JWT-based authentication with 24-hour session
- Role-based access control (super_admin, admin, moderator)
- Automatic logout on session expiration

### 📊 Dashboard Overview
- Real-time statistics display
- Total users, messages, reports, and banned users
- Today's new registrations and reports
- Interactive charts showing user registration trends
- System activity overview

### 👥 User Management
- View all registered users with search and filtering
- User details including profile pictures, join dates, and status
- Ban users temporarily or permanently
- Unban users with one click
- View ban history and reasons
- Filter users by status (active/banned)

### 🚩 Report Management
- View all user reports with detailed information
- Report status tracking (pending, reviewed, resolved, dismissed)
- Filter reports by status
- Take action on reports (resolve, dismiss)
- View reporter and reported user details

### 📈 Analytics
- User registration trends over time (7, 30, 90 days)
- Message activity analytics
- Report submission trends
- Interactive charts with Chart.js
- Exportable data for further analysis

### 🛡️ Security Features
- Automatic temporary ban expiration
- Ban enforcement on protected routes
- Secure admin session management
- Input validation and sanitization

## Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- MongoDB
- All dependencies from package.json

### Default Admin Account
When the server starts for the first time, a default admin account is automatically created:

- **Username:** `admin`
- **Password:** `admin123`
- **Role:** `super_admin`
- **Email:** `admin@bawi.com`

⚠️ **Important:** Change the default password immediately after first login!

### Accessing the Admin Dashboard

1. Start the server: `npm start`
2. Navigate to: `http://localhost:3000/admin/login`
3. Login with admin credentials
4. Access dashboard at: `http://localhost:3000/admin/dashboard`

## API Endpoints

### Authentication
- `POST /api/admin/login` - Admin login
- `POST /api/admin/logout` - Admin logout

### Statistics
- `GET /api/admin/stats` - Get dashboard statistics
- `GET /api/admin/analytics` - Get analytics data

### User Management
- `GET /api/admin/users` - Get users with pagination and filtering
- `POST /api/admin/ban-user` - Ban a user
- `POST /api/admin/unban-user` - Unban a user

### Report Management
- `GET /api/admin/reports` - Get reports with pagination and filtering
- `POST /api/admin/update-report-status` - Update report status

## User Banning System

### Ban Types
1. **Temporary Ban**
   - Duration specified in hours
   - Automatic expiration
   - User can return after ban expires

2. **Permanent Ban**
   - No expiration date
   - Requires manual unban by admin
   - User cannot access the platform

### Ban Enforcement
- Banned users are blocked from accessing dashboard and chat rooms
- Clear ban message displayed with reason and expiration (if temporary)
- Session terminated immediately upon ban detection

### Auto-Unban System
- Cron job runs every hour to check for expired temporary bans
- Automatically deactivates expired bans
- Logs unban activities for audit trail

## Admin Roles & Permissions

### Super Admin
- Full access to all features
- Can manage other admin accounts
- Can view system logs and analytics
- Can perform all user management actions

### Admin
- Can manage users and reports
- Can view analytics
- Cannot manage other admin accounts
- Full user management permissions

### Moderator
- Can view reports and take action
- Limited user management (view only)
- Cannot ban users
- Cannot access analytics

## Security Considerations

### Session Management
- JWT tokens with 24-hour expiration
- HttpOnly cookies for token storage
- Automatic session cleanup
- Secure token verification

### Input Validation
- All admin inputs are validated and sanitized
- SQL injection prevention through Mongoose
- XSS protection through proper escaping
- CSRF protection through secure tokens

### Access Control
- Route-level authentication middleware
- Role-based permission checking
- Secure admin-only endpoints
- Session hijacking prevention

## Monitoring & Logging

### Activity Logging
- Admin login/logout events
- User ban/unban actions
- Report status changes
- System errors and warnings

### Performance Monitoring
- Database query optimization
- Response time tracking
- Memory usage monitoring
- Error rate tracking

## Troubleshooting

### Common Issues

1. **Admin Login Fails**
   - Check if default admin account exists
   - Verify MongoDB connection
   - Check server logs for errors

2. **Charts Not Loading**
   - Ensure Chart.js is properly loaded
   - Check browser console for JavaScript errors
   - Verify API endpoints are responding

3. **Ban System Not Working**
   - Check if UserBan model is properly defined
   - Verify cron job is running
   - Check MongoDB for ban records

4. **Reports Not Showing**
   - Verify Report model exists
   - Check if reports have proper user references
   - Ensure proper population of user data

### Debug Mode
Enable debug logging by setting environment variable:
```bash
DEBUG=admin:*
npm start
```

## Future Enhancements

### Planned Features
- [ ] Advanced analytics with machine learning insights
- [ ] Bulk user operations
- [ ] Email notifications for admins
- [ ] Audit trail and activity logs
- [ ] Two-factor authentication for admins
- [ ] API rate limiting
- [ ] Real-time notifications
- [ ] Export functionality for reports
- [ ] Advanced search and filtering
- [ ] Mobile-responsive admin interface

### Performance Optimizations
- [ ] Database indexing for faster queries
- [ ] Caching for frequently accessed data
- [ ] Pagination optimization
- [ ] Image compression for user avatars
- [ ] CDN integration for static assets

## Support

For technical support or feature requests, please contact the development team or create an issue in the project repository.

---

**Note:** This admin dashboard is designed for internal use only. Ensure proper security measures are in place before deploying to production. 