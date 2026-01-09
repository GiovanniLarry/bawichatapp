const fs = require('fs');
const path = require('path');
const CleanCSS = require('clean-css');

// Create production build
console.log('🏗️  Building production version...');

// Minify CSS
const cleanCSS = new CleanCSS();
const cssPath = path.join(__dirname, 'styles', 'main.css');
const minCssPath = path.join(__dirname, 'styles', 'main.min.css');

try {
  const cssContent = fs.readFileSync(cssPath, 'utf8');
  const minifiedCSS = cleanCSS.minify(cssContent);
  
  fs.writeFileSync(minCssPath, minifiedCSS.styles);
  console.log(`✅ CSS minified: ${(fs.statSync(cssPath).size / 1024).toFixed(2)}KB → ${(fs.statSync(minCssPath).size / 1024).toFixed(2)}KB`);
} catch (error) {
  console.error('❌ Error minifying CSS:', error.message);
}

// Create production environment file
const prodEnv = `NODE_ENV=production
MONGODB_URI=${process.env.MONGODB_URI || 'mongodb://localhost:27017/chat-app'}
JWT_SECRET=${process.env.JWT_SECRET || 'your-production-jwt-secret-here'}
`;

fs.writeFileSync(path.join(__dirname, '.env.production'), prodEnv);
console.log('✅ Production environment file created');

// Create build info
const buildInfo = {
  buildTime: new Date().toISOString(),
  version: require('./package.json').version,
  environment: 'production'
};

fs.writeFileSync(path.join(__dirname, 'build-info.json'), JSON.stringify(buildInfo, null, 2));
console.log('✅ Build info created');

console.log('🚀 Production build complete!');
console.log('\n📋 Next steps:');
console.log('1. Set your environment variables in .env.production');
console.log('2. Deploy to Vercel: vercel --prod');
console.log('3. Or run locally: NODE_ENV=production npm start');
