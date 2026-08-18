import React, { useEffect, useState, useCallback } from 'react';
import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
  Alert
} from '@mui/material';
import { Delete as DeleteIcon, Edit as EditIcon } from '@mui/icons-material';
import { PageHeader, LoadingState, ErrorState } from '../components/ui';
import { getTenantUsers, updateUser, deleteUser, User } from '../services/api';
import { useAuthStore, usePermissionStore } from '../store';

const UsersPage: React.FC = () => {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [deleteConfirmUser, setDeleteConfirmUser] = useState<User | null>(null);
  const { user: currentUser } = useAuthStore();
  const can = usePermissionStore((state) => state.can);

  const fetchUsers = useCallback(async () => {
    try {
      setLoading(true);
      setFetchError(null);
      const data = await getTenantUsers();
      setUsers(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setFetchError(err?.response?.data?.detail || err?.message || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!currentUser) {
      return; // Still loading
    }

    fetchUsers();
  }, [currentUser, fetchUsers]);

  const handleSaveUser = async () => {
    if (!editUser) return;
    try {
      await updateUser(editUser.id, {
        full_name: editUser.full_name,
        is_active: editUser.is_active,
      });
      setEditUser(null);
      fetchUsers();
    } catch (err: any) {
      setFetchError(err.response?.data?.detail || 'Failed to update user');
    }
  };

  const handleDeleteUser = async () => {
    if (!deleteConfirmUser) return;
    try {
      await deleteUser(deleteConfirmUser.id);
      setDeleteConfirmUser(null);
      fetchUsers();
    } catch (err: any) {
      setFetchError(err.response?.data?.detail || 'Failed to deactivate user');
    }
  };

  const getRoleColor = (role?: string) => {
    if (!role) return 'default';
    switch (role.toLowerCase()) {
      case 'admin':
        return 'error';
      case 'analyst':
        return 'primary';
      case 'responder':
        return 'warning';
      case 'viewer':
        return 'default';
      default:
        return 'default';
    }
  };

  const isCurrentUser = (u: User | null): boolean => {
    return !!(currentUser && u && currentUser.id === u.id);
  };

  if (!currentUser) {
    return <LoadingState title="Loading user permissions..." />;
  }

  if (loading) {
    return <LoadingState />;
  }

  if (fetchError) {
    return <ErrorState message={fetchError} onRetry={fetchUsers} />;
  }

  return (
    <Box sx={{ maxWidth: 1200, mx: 'auto' }}>
      <PageHeader
        title="User Management"
        description="Manage users and their roles"
      />

      <Card sx={{ mt: 3 }}>
        <CardContent sx={{ p: 0 }}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Email</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {users.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} align="center">
                    <Typography>No users found</Typography>
                  </TableCell>
                </TableRow>
              ) : (
                users.map((u) => (
                  <TableRow key={u.id || u.email}>
                    <TableCell>
                      <Typography variant="body1">
                        {u.full_name || 'Unnamed User'}
                      </Typography>
                    </TableCell>
                    <TableCell>{u.email}</TableCell>
                    <TableCell>
                      <Chip
                        label={u.role || 'unknown'}
                        color={getRoleColor(u.role)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={u.is_active ? 'Active' : 'Inactive'}
                        color={u.is_active ? 'success' : 'default'}
                        size="small"
                      />
                    </TableCell>
                    <TableCell align="right">
                      {can('users.update') && <Button
                        variant="outlined"
                        size="small"
                        startIcon={<EditIcon />}
                        onClick={() => setEditUser({ ...u })}
                        sx={{ mr: 1 }}
                      >
                        Edit
                      </Button>}
                      {can('users.disable') && <Button
                        variant="outlined"
                        size="small"
                        color="error"
                        startIcon={<DeleteIcon />}
                        onClick={() => setDeleteConfirmUser(u)}
                        disabled={isCurrentUser(u)}
                      >
                        Deactivate
                      </Button>}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Edit Dialog */}
      <Dialog open={!!editUser} onClose={() => setEditUser(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Edit User</DialogTitle>
        <DialogContent sx={{ pt: 1 }}>
          {editUser && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
              <TextField
                label="Full Name"
                value={editUser.full_name || ''}
                onChange={(e) => setEditUser({ ...editUser, full_name: e.target.value })}
                fullWidth
              />
              <Alert severity="info">
                Assign organization roles and membership status from the Members page.
              </Alert>
              {isCurrentUser(editUser) && (
                <Alert severity="info">
                  You cannot modify your own administrator account
                </Alert>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditUser(null)}>Cancel</Button>
          <Button
            onClick={handleSaveUser}
            variant="contained"
            disabled={isCurrentUser(editUser)}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation */}
      <Dialog
        open={!!deleteConfirmUser}
        onClose={() => setDeleteConfirmUser(null)}
      >
        <DialogTitle>Deactivate User</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to deactivate {deleteConfirmUser?.email}?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirmUser(null)}>Cancel</Button>
          <Button onClick={handleDeleteUser} color="error" variant="contained">
            Deactivate
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UsersPage;
