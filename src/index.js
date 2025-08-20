import * as dotenv from 'dotenv';
import { app } from './app.js';

dotenv.config();

(function serverRun(){
    try {
        app.listen(process.env.PORT || 3000, () => {
            console.log(`Server is running at port: ${process.env.PORT}`);
        })

        app.on("error", error => {
            console.log("ERR: ", error)
            throw error
        })
    } catch (error) {
        console.log("There is and error while initializing the server!")
    }
})();
