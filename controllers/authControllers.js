const adminModel = require("../models/adminModel");
const { responseReturn } = require("../utilities/response");
const bcrypt = require("bcrypt");
const { createToken } = require("../utilities/tokenCreate");

class authcontrollers {
  admin_login = async (req, res) => {
    const { email, password } = req.body;
    try {
      const admin = await adminModel.findOne({ email }).select("+password");

      if (admin) {
        console.log(`Admin encontrado: ${admin.email}`);
        const match = await bcrypt.compare(password, admin.password);
        console.log(`Comparación de contraseñas: ${match}`);
        if (match) {
          const token = await createToken({
            id: admin.id,
            role: admin.role,
          });
          res.cookie("accesTokenEcommerce", token, {
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          });
          responseReturn(res, 200, { token, message: "Iniciando sesion..." });
        } else {
          responseReturn(res, 401, {
            error: "El correo y/o contraseña son incorrectos",
          });
        }
      } else {
        responseReturn(res, 404, { error: "El correo no esta registrado" });
      }
    } catch (error) {
      console.error(`Error en admin_login: ${error.message}`);
      responseReturn(res, 500, { error: error.message });
    }
  };
}

module.exports = new authcontrollers();
