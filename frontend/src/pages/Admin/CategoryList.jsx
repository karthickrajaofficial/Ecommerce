import { useState } from "react";
import {
  useCreateCategoryMutation,
  useUpdateCategoryMutation,
  useDeleteCategoryMutation,
  useFetchCategoriesQuery,
} from "../../redux/api/categoryApiSlice";

import { toast } from "react-toastify";
// import CategoryForm from "../../components/CategoryForm";
// import Modal from "../../components/Modal";

const CategoryList = () => {
    const { data: categories } = useFetchCategoriesQuery();
    const [name, setName] = useState("");
    const [selectedCategory, setSelectedCategory] = useState(null);
    const [updatingName, setUpdatingName] = useState("");
    const [modalVisible, setModalVisible] = useState(false);
  
    const [createCategory] = useCreateCategoryMutation();
    const [updateCategory] = useUpdateCategoryMutation();
    const [deleteCategory] = useDeleteCategoryMutation();

  return (
    <div className="ml-[10rem] flex flex-col md:flex-row  ">
        {/* adminmenu */}
        <div className="md:w-3/4 p-3">
            <div className="h-12">Mange Categories</div>
        </div>
    </div>
  )
}

export default CategoryList