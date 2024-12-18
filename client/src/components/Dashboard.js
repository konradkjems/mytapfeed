import React, { useState, useEffect } from 'react';
import {
    Container,
    Grid,
    Paper,
    Typography,
    Button,
    Box,
    Tab,
    Tabs,
    Dialog,
    DialogTitle,
    DialogContent,
    DialogActions,
    TextField,
    IconButton,
    Menu,
    MenuItem,
    Divider,
    ViewListIcon
} from '@mui/material';
import { DragDropContext, Droppable, Draggable } from 'react-beautiful-dnd';
import AddIcon from '@mui/icons-material/Add';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import DragHandleIcon from '@mui/icons-material/DragHandle';
import CategoryManager from './CategoryManager';
import LandingPageEditor from './LandingPageEditor';
import QRCode from 'qrcode.react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

function Dashboard() {
    const [stands, setStands] = useState([]);
    const [categories, setCategories] = useState([]);
    const [selectedCategory, setSelectedCategory] = useState('all');
    const [openDialog, setOpenDialog] = useState(false);
    const [openLandingPageDialog, setOpenLandingPageDialog] = useState(false);
    const [selectedStand, setSelectedStand] = useState(null);
    const [anchorEl, setAnchorEl] = useState(null);
    const [formData, setFormData] = useState({
        standerId: '',
        redirectUrl: '',
        productType: 'stander'
    });

    useEffect(() => {
        fetchStands();
        fetchCategories();
    }, []);

    const fetchStands = async () => {
        try {
            const response = await fetch('/api/stands', {
                credentials: 'include'
            });
            if (response.ok) {
                const data = await response.json();
                setStands(data);
            }
        } catch (error) {
            console.error('Fejl ved hentning af stands:', error);
        }
    };

    const fetchCategories = async () => {
        try {
            const response = await fetch('/api/categories', {
                credentials: 'include'
            });
            if (response.ok) {
                const data = await response.json();
                setCategories(data);
            }
        } catch (error) {
            console.error('Fejl ved hentning af kategorier:', error);
        }
    };

    const handleCategoryChange = async (action, category) => {
        try {
            let response;
            switch (action) {
                case 'create':
                    response = await fetch('/api/categories', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify(category)
                    });
                    break;
                case 'update':
                    response = await fetch(`/api/categories/${category._id}`, {
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify(category)
                    });
                    break;
                case 'delete':
                    response = await fetch(`/api/categories/${category._id}`, {
                        method: 'DELETE',
                        credentials: 'include'
                    });
                    break;
                default:
                    return;
            }

            if (response.ok) {
                fetchCategories();
                fetchStands();
            }
        } catch (error) {
            console.error('Fejl ved håndtering af kategori:', error);
        }
    };

    const handleCategoryReorder = async (newCategories) => {
        try {
            const response = await fetch('/api/categories/reorder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ categories: newCategories })
            });

            if (response.ok) {
                setCategories(newCategories);
            }
        } catch (error) {
            console.error('Fejl ved omarrangering af kategorier:', error);
        }
    };

    const handleStandReorder = async (newStands) => {
        try {
            const response = await fetch('/api/stands/reorder', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ stands: newStands })
            });

            if (response.ok) {
                setStands(newStands);
            }
        } catch (error) {
            console.error('Fejl ved omarrangering af stands:', error);
        }
    };

    const onDragEnd = (result) => {
        if (!result.destination) return;

        const { source, destination, type } = result;

        if (type === 'category') {
            const items = Array.from(categories);
            const [reorderedItem] = items.splice(source.index, 1);
            items.splice(destination.index, 0, reorderedItem);
            handleCategoryReorder(items);
        } else {
            const items = Array.from(stands);
            const [reorderedItem] = items.splice(source.index, 1);
            items.splice(destination.index, 0, reorderedItem);
            handleStandReorder(items);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const response = await fetch('/api/stands', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    ...formData,
                    categoryId: selectedCategory !== 'all' ? selectedCategory : null
                }),
            });

            if (response.ok) {
                setOpenDialog(false);
                setFormData({
                    standerId: '',
                    redirectUrl: '',
                    productType: 'stander'
                });
                fetchStands();
            }
        } catch (error) {
            console.error('Fejl ved oprettelse af stand:', error);
        }
    };

    const handleStandClick = (stand) => {
        setSelectedStand(stand);
        setAnchorEl(null);
        setOpenLandingPageDialog(true);
    };

    const handleLandingPageSave = async (landingPageData) => {
        try {
            const response = await fetch(`/api/stands/${selectedStand._id}/landing-page`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify(landingPageData),
            });

            if (response.ok) {
                setOpenLandingPageDialog(false);
                fetchStands();
            }
        } catch (error) {
            console.error('Fejl ved opdatering af landing page:', error);
        }
    };

    const handleDeleteStand = async (standId) => {
        try {
            const response = await fetch(`/api/stands/${standId}`, {
                method: 'DELETE',
                credentials: 'include',
            });

            if (response.ok) {
                fetchStands();
            }
        } catch (error) {
            console.error('Fejl ved sletning af stand:', error);
        }
    };

    const downloadQRCode = (standerId) => {
        const canvas = document.getElementById(`qr-${standerId}`);
        if (canvas) {
            const pngUrl = canvas
                .toDataURL("image/png")
                .replace("image/png", "image/octet-stream");
            let downloadLink = document.createElement("a");
            downloadLink.href = pngUrl;
            downloadLink.download = `qr-${standerId}.png`;
            document.body.appendChild(downloadLink);
            downloadLink.click();
            document.body.removeChild(downloadLink);
        }
    };

    const filteredStands = selectedCategory === 'all'
        ? stands
        : stands.filter(stand => stand.categoryId === selectedCategory);

    const getClickData = () => {
        const last7Days = [...Array(7)].map((_, i) => {
            const d = new Date();
            d.setDate(d.getDate() - i);
            return d.toISOString().split('T')[0];
        }).reverse();

        return last7Days.map(date => {
            const clicks = stands.reduce((total, stand) => {
                return total + (stand.clickHistory || []).filter(click => 
                    click.timestamp.split('T')[0] === date
                ).length;
            }, 0);
            return {
                date: date,
                clicks: clicks
            };
        });
    };

    return (
        <Container maxWidth="lg" sx={{ mt: 4, mb: 4 }}>
            <Grid container spacing={3}>
                <Grid item xs={12}>
                    <Paper sx={{ p: 2, display: 'flex', flexDirection: 'column' }}>
                        <Typography component="h2" variant="h6" color="primary" gutterBottom>
                            Klik Statistik
                        </Typography>
                        <BarChart
                            width={800}
                            height={300}
                            data={getClickData()}
                            margin={{
                                top: 5,
                                right: 30,
                                left: 20,
                                bottom: 5,
                            }}
                        >
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="date" />
                            <YAxis />
                            <Tooltip />
                            <Legend />
                            <Bar dataKey="clicks" fill="#8884d8" name="Antal klik" />
                        </BarChart>
                    </Paper>
                </Grid>

                <Grid item xs={12}>
                    <CategoryManager
                        categories={categories}
                        onCategoryChange={handleCategoryChange}
                        onCategoryReorder={handleCategoryReorder}
                    />
                </Grid>

                <Grid item xs={12}>
                    <Paper sx={{ p: 2 }}>
                        <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                            <Typography component="h2" variant="h6" color="primary">
                                Produkter
                            </Typography>
                            <Button
                                variant="contained"
                                color="primary"
                                startIcon={<AddIcon />}
                                onClick={() => setOpenDialog(true)}
                            >
                                Tilføj Produkt
                            </Button>
                        </Box>

                        <Tabs
                            value={selectedCategory}
                            onChange={(e, newValue) => setSelectedCategory(newValue)}
                            sx={{ mb: 2 }}
                        >
                            <Tab label="Alle" value="all" />
                            {categories.map((category) => (
                                <Tab key={category._id} label={category.name} value={category._id} />
                            ))}
                        </Tabs>

                        <DragDropContext onDragEnd={onDragEnd}>
                            <Droppable droppableId="stands">
                                {(provided) => (
                                    <div {...provided.droppableProps} ref={provided.innerRef}>
                                        <Grid container spacing={2}>
                                            {filteredStands.map((stand, index) => (
                                                <Draggable
                                                    key={stand._id}
                                                    draggableId={stand._id}
                                                    index={index}
                                                >
                                                    {(provided) => (
                                                        <Grid item xs={12} sm={6} md={4}
                                                            ref={provided.innerRef}
                                                            {...provided.draggableProps}
                                                        >
                                                            <Paper sx={{ p: 2, position: 'relative' }}>
                                                                <Box {...provided.dragHandleProps} 
                                                                    sx={{ 
                                                                        position: 'absolute',
                                                                        top: 8,
                                                                        left: 8,
                                                                        cursor: 'move'
                                                                    }}
                                                                >
                                                                    <DragHandleIcon />
                                                                </Box>
                                                                <Box sx={{ ml: 4 }}>
                                                                    <Box display="flex" justifyContent="space-between" alignItems="center">
                                                                        <Typography variant="h6">
                                                                            {stand.standerId}
                                                                        </Typography>
                                                                        <IconButton
                                                                            onClick={(e) => {
                                                                                setSelectedStand(stand);
                                                                                setAnchorEl(e.currentTarget);
                                                                            }}
                                                                        >
                                                                            <MoreVertIcon />
                                                                        </IconButton>
                                                                    </Box>
                                                                    <Typography color="textSecondary" gutterBottom>
                                                                        {stand.productType}
                                                                    </Typography>
                                                                    <Typography variant="body2" gutterBottom>
                                                                        URL: {stand.redirectUrl}
                                                                    </Typography>
                                                                    <Box mt={2} display="flex" justifyContent="center">
                                                                        <QRCode
                                                                            id={`qr-${stand.standerId}`}
                                                                            value={`${window.location.origin}/${stand.standerId}`}
                                                                            size={128}
                                                                            level="H"
                                                                            onClick={() => downloadQRCode(stand.standerId)}
                                                                            style={{ cursor: 'pointer' }}
                                                                        />
                                                                    </Box>
                                                                    <Typography variant="body2" color="textSecondary" align="center" mt={1}>
                                                                        Klik for at downloade QR kode
                                                                    </Typography>
                                                                </Box>
                                                            </Paper>
                                                        </Grid>
                                                    )}
                                                </Draggable>
                                            ))}
                                        </Grid>
                                        {provided.placeholder}
                                    </div>
                                )}
                            </Droppable>
                        </DragDropContext>
                    </Paper>
                </Grid>
            </Grid>

            <Dialog open={openDialog} onClose={() => setOpenDialog(false)}>
                <DialogTitle>Tilføj Nyt Produkt</DialogTitle>
                <DialogContent>
                    <TextField
                        autoFocus
                        margin="dense"
                        label="Produkt ID"
                        type="text"
                        fullWidth
                        value={formData.standerId}
                        onChange={(e) => setFormData({ ...formData, standerId: e.target.value })}
                    />
                    <TextField
                        margin="dense"
                        label="Redirect URL"
                        type="text"
                        fullWidth
                        value={formData.redirectUrl}
                        onChange={(e) => setFormData({ ...formData, redirectUrl: e.target.value })}
                    />
                    <TextField
                        margin="dense"
                        label="Produkt Type"
                        select
                        fullWidth
                        value={formData.productType}
                        onChange={(e) => setFormData({ ...formData, productType: e.target.value })}
                    >
                        <MenuItem value="stander">Stander</MenuItem>
                        <MenuItem value="sticker">Sticker</MenuItem>
                        <MenuItem value="kort">Kort</MenuItem>
                        <MenuItem value="plate">Skilt</MenuItem>
                    </TextField>
                </DialogContent>
                <DialogActions>
                    <Button onClick={() => setOpenDialog(false)}>Annuller</Button>
                    <Button onClick={handleSubmit} color="primary">Tilføj</Button>
                </DialogActions>
            </Dialog>

            <Dialog 
                open={openLandingPageDialog} 
                onClose={() => setOpenLandingPageDialog(false)}
                maxWidth="md"
                fullWidth
            >
                <DialogContent>
                    <LandingPageEditor
                        stand={selectedStand}
                        onSave={handleLandingPageSave}
                    />
                </DialogContent>
            </Dialog>

            <Menu
                anchorEl={anchorEl}
                open={Boolean(anchorEl)}
                onClose={() => setAnchorEl(null)}
            >
                <MenuItem onClick={() => handleStandClick(selectedStand)}>
                    Rediger Landing Page
                </MenuItem>
                <Divider />
                <MenuItem onClick={() => {
                    handleDeleteStand(selectedStand._id);
                    setAnchorEl(null);
                }} sx={{ color: 'error.main' }}>
                    Slet Produkt
                </MenuItem>
            </Menu>
        </Container>
    );
}

export default Dashboard; 