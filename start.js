import 'dotenv/config';

const { default: app } = await import('./server.js');

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Hina Home listening on ${port}`));
