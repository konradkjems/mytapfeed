import React, { useState } from 'react';
import {
    Box,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    TextField,
    List,
    ListItem,
    ListItemText,
    ListItemSecondaryAction,
    IconButton,
    Typography
} from '@mui/material';
import { DragDropContext, Droppable, Draggable } from 'react-beautiful-dnd';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import DragHandleIcon from '@mui/icons-material/DragHandle';

const CategoryManager = ({ categories, onCategoryChange, onCategoryReorder }) => {
    const [open, setOpen] = useState(false);
    const [editingCategory, setEditingCategory] = useState(null);
    const [categoryName, setCategoryName] = useState('');
    const [categoryDescription, setCategoryDescription] = useState('');

    const handleOpen = (category = null) => {
        if (category) {
            setEditingCategory(category);
            setCategoryName(category.name);
            setCategoryDescription(category.description || '');
        } else {
            setEditingCategory(null);
            setCategoryName('');
            setCategoryDescription('');
        }
        setOpen(true);
    };

    const handleClose = () => {
        setOpen(false);
        setEditingCategory(null);
        setCategoryName('');
        setCategoryDescription('');
    };

    const handleSave = () => {
        const categoryData = {
            name: categoryName,
            description: categoryDescription
        };

        if (editingCategory) {
            onCategoryChange('update', { ...editingCategory, ...categoryData });
        } else {
            onCategoryChange('create', categoryData);
        }

        handleClose();
    };

    const handleDelete = (category) => {
        onCategoryChange('delete', category);
    };

    const onDragEnd = (result) => {
        if (!result.destination) return;

        const items = Array.from(categories);
        const [reorderedItem] = items.splice(result.source.index, 1);
        items.splice(result.destination.index, 0, reorderedItem);

        onCategoryReorder(items);
    };

    return (
        <Box>
            <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                <Typography variant="h6">Kategorier</Typography>
                <Button variant="contained" color="primary" onClick={() => handleOpen()}>
                    Tilføj Kategori
                </Button>
            </Box>

            <DragDropContext onDragEnd={onDragEnd}>
                <Droppable droppableId="categories">
                    {(provided) => (
                        <List {...provided.droppableProps} ref={provided.innerRef}>
                            {categories.map((category, index) => (
                                <Draggable 
                                    key={category._id} 
                                    draggableId={category._id} 
                                    index={index}
                                >
                                    {(provided) => (
                                        <ListItem
                                            ref={provided.innerRef}
                                            {...provided.draggableProps}
                                            divider
                                        >
                                            <Box {...provided.dragHandleProps} mr={2}>
                                                <DragHandleIcon />
                                            </Box>
                                            <ListItemText
                                                primary={category.name}
                                                secondary={category.description}
                                            />
                                            <ListItemSecondaryAction>
                                                <IconButton 
                                                    edge="end" 
                                                    aria-label="edit"
                                                    onClick={() => handleOpen(category)}
                                                    sx={{ mr: 1 }}
                                                >
                                                    <EditIcon />
                                                </IconButton>
                                                <IconButton 
                                                    edge="end" 
                                                    aria-label="delete"
                                                    onClick={() => handleDelete(category)}
                                                >
                                                    <DeleteIcon />
                                                </IconButton>
                                            </ListItemSecondaryAction>
                                        </ListItem>
                                    )}
                                </Draggable>
                            ))}
                            {provided.placeholder}
                        </List>
                    )}
                </Droppable>
            </DragDropContext>

            <Dialog open={open} onClose={handleClose}>
                <DialogTitle>
                    {editingCategory ? 'Rediger Kategori' : 'Ny Kategori'}
                </DialogTitle>
                <DialogContent>
                    <TextField
                        autoFocus
                        margin="dense"
                        label="Kategorinavn"
                        type="text"
                        fullWidth
                        value={categoryName}
                        onChange={(e) => setCategoryName(e.target.value)}
                    />
                    <TextField
                        margin="dense"
                        label="Beskrivelse"
                        type="text"
                        fullWidth
                        multiline
                        rows={3}
                        value={categoryDescription}
                        onChange={(e) => setCategoryDescription(e.target.value)}
                    />
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleClose}>Annuller</Button>
                    <Button onClick={handleSave} color="primary">
                        Gem
                    </Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
};

export default CategoryManager; 