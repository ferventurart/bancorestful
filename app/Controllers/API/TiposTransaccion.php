<?php namespace App\Controllers\API;

use App\Models\TipoTransaccionModel;
use CodeIgniter\RESTful\ResourceController;

class TiposTransaccion extends ResourceController
{
    public function __construct() {
        $this->model = $this->setModel(new TipoTransaccionModel());
    }

	public function index()
	{
        $tiposTransaccion = $this->model->findAll();
        return $this->respond($tiposTransaccion);
    } 
    
    public function create()
    {
        try {

            $tipoTransaccion = $this->request->getJSON();
            if($this->model->insert($tipoTransaccion)):
                $tipoTransaccion->id = $this->model->insertID();
                return $this->respondCreated($tipoTransaccion);
            else:
                return $this->failValidationError($this->model->validation->listErrors());
            endif;
        } catch (\Exception $e) {
            return $this->failServerError('Ha ocurrido un error en el servidor');
        }
    }

    public function edit($id = null)
	{
        try {

            if($id == null)
                return $this->failValidationError('No se ha pasado un Id valido');

            $tipoTransaccion = $this->model->find($id);
            if($tipoTransaccion == null)
                return $this->failNotFound('No se ha encontrado un Tipo de Transaccion con el id: '.$id);

            return $this->respond($tipoTransaccion);

        } catch (\Exception $e) {
            return $this->failServerError('Ha ocurrido un error en el servidor');
        }
    }
    
    public function update($id = null)
	{
        try {

            if($id == null)
                return $this->failValidationError('No se ha pasado un Id valido');

            $tipoTransaccionVerificado = $this->model->find($id);
            if($tipoTransaccionVerificado == null)
                return $this->failNotFound('No se ha encontrado un Tipo de Transaccion con el id: '.$id);

            $tipoTransaccion = $this->request->getJSON();

            if($this->model->update($id, $tipoTransaccion)):
                $tipoTransaccion->id = $id;
                return $this->respondUpdated($tipoTransaccion);
            else:
                return $this->failValidationError($this->model->validation->listErrors());
            endif;

        } catch (\Exception $e) {
            return $this->failServerError('Ha ocurrido un error en el servidor');
        }
    }
    
    public function delete($id = null)
	{
        try {

            if($id == null)
                return $this->failValidationError('No se ha pasado un Id valido');

            $tipoTransaccionVerificado = $this->model->find($id);
            if($tipoTransaccionVerificado == null)
                return $this->failNotFound('No se ha encontrado un tipoTransaccion con el id: '.$id);

            if($this->model->delete($id)):
                return $this->respondDeleted($tipoTransaccionVerificado);
            else:
                return $this->failServerError('No se ha podido eliminar el registro');
            endif;

        } catch (\Exception $e) {
            return $this->failServerError('Ha ocurrido un error en el servidor');
        }
	}

}
