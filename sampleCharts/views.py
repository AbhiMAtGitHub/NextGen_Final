from django.shortcuts import render, redirect
from django.contrib import messages
from backend import settings
from .forms import CSVUploadForm
import joblib
import os
import pandas as pd
from django.shortcuts import render
import json
from django.http import JsonResponse

def prediction(request):
    if request.method == 'POST':
        chart_data = None
        images_present = False
        
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            csv_file = request.FILES['csv_file']
            
            if not csv_file:
                messages.error(request, "No file uploaded.")
                return redirect('predict')
           
            if not csv_file.name.endswith('.csv'):
                messages.error(request, "Please upload a CSV file.")
                return redirect('predict')
 
            try:
                sample_data = pd.read_csv(csv_file)
                
                # Preprocess the data
                sample_data['PurchaseDate'] = pd.to_datetime(sample_data['PurchaseDate'])
                sample_data['Year'] = sample_data['PurchaseDate'].dt.year
                sample_data['Month'] = sample_data['PurchaseDate'].dt.month
                sample_data['Day'] = sample_data['PurchaseDate'].dt.day
                sample_data['Quantity'] = pd.to_numeric(sample_data['Quantity'])
                
            except Exception as e:
                messages.error(request, f'Error reading CSV: {e}')
                return redirect('predict')
                           
            model_path = settings.ML_MODEL_PATH
 
            if not os.path.exists(model_path):
                messages.error(request, "Model file not found.")
                return redirect('predict')
                 
            try:
                model = joblib.load(model_path)
            except Exception as e:
                messages.error(request, f'Error loading model: {e}')
                return redirect('predict')
             
            try:
                # Test the model
                sample_data['PredictedTotalAmount'] = model.predict(sample_data[['Year', 'Month', 'Day', 'Quantity']])

                # Scenario 1: Line graph Plotting the line graph for Predicted TotalAmount & Actual TotalAmount vs PurchaseDate
                sample_data_month = sample_data.groupby(['Year', 'Month']).agg({
                    'PurchaseDate': 'max',
                    'TotalAmount': 'sum',
                    'PredictedTotalAmount': 'sum'
                }).reset_index()

                sample_data_month['PurchaseDate'] = pd.to_datetime(sample_data_month[['Year', 'Month']].assign(DAY=1))
                
                # Prepare chart data for Scenario 5: Line graph for predicted TotalAmount vs next 6 months
                last_purchase_date = sample_data['PurchaseDate'].max()
                next_6_months = pd.date_range(start=last_purchase_date, periods=6, freq='ME')
                future_data = pd.DataFrame({'Year': next_6_months.year,
                                            'Month': next_6_months.month,
                                            'Day': 1,  # Default to 1 for the day
                                            'Quantity': 1})  # Assume quantity as 1 for prediction
                future_data['PredictedTotalAmount'] = model.predict(future_data[['Year', 'Month', 'Day', 'Quantity']])
                future_data['PurchaseDate'] = next_6_months
                # Prepare chart data
                chart_data = {
                    'labels': sample_data_month['PurchaseDate'].dt.strftime('%Y').tolist(),
                    'predicted_amount': sample_data_month['PredictedTotalAmount'].tolist(),
                    'actual_amount': sample_data_month['TotalAmount'].tolist(),
                    
                    'category_labels': sample_data['Category'].value_counts().index.tolist(),
                    'category_counts': sample_data['Category'].value_counts().tolist(),
                    
                    'top_products': sample_data.groupby('ProductName')['Quantity'].sum().nlargest(10).index.tolist(),
                    'top_products_quantities': sample_data.groupby('ProductName')['Quantity'].sum().nlargest(10).tolist(),

                    'purchase_dates': sample_data_month['PurchaseDate'].dt.strftime('%Y-%m').tolist(),
                    'total_amounts': sample_data_month['TotalAmount'].tolist(),
                    
                    'future_purchase_dates': future_data['PurchaseDate'].dt.strftime('%Y-%m').tolist(),
                    'predicted_total_amounts': future_data['PredictedTotalAmount'].tolist(),
                }
                
                images_present = True
            except Exception as e:
                messages.error(request, f'Error in prediction or data processing: {e}')
                return redirect('predict')
        return render(request, 'dash1.html', {
            
            'form': form,
            'chart_data': json.dumps(chart_data),
            'images_present': images_present,
        })
    elif request.method == "GET":
        form = CSVUploadForm()
        images_present = False
        
        return render(request, 'dash1.html', {
            
            'form': form,
            'images_present': images_present,
        })
